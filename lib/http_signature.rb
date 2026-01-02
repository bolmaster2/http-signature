# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'base64'
require 'uri'
require 'digest'
require 'rack/utils'

# Implements HTTP Message Signatures per RFC 9421.
module HTTPSignature
  Config = Struct.new(:keys)
  DEFAULT_LABEL = 'sig1'
  DEFAULT_ALGORITHM = 'hmac-sha256'
  DEFAULT_COMPONENTS = %w[@method @authority @target-uri].freeze

  class SignatureError < StandardError; end
  class MissingComponent < SignatureError; end
  class UnsupportedAlgorithm < SignatureError; end

  Algorithm = Struct.new(:type, :digest_name, :curve)
  ALGORITHMS = {
    # HMAC algorithms (Section 3.3.3)
    'hmac-sha256' => Algorithm.new(:hmac, 'SHA256'),
    'hmac-sha512' => Algorithm.new(:hmac, 'SHA512'),
    # RSA-PSS algorithms (Section 3.3.1)
    'rsa-pss-sha256' => Algorithm.new(:rsa_pss, 'SHA256'),
    'rsa-pss-sha512' => Algorithm.new(:rsa_pss, 'SHA512'),
    # RSASSA-PKCS1-v1_5 algorithms (Section 3.3.2)
    'rsa-v1_5-sha256' => Algorithm.new(:rsa, 'SHA256'),
    # ECDSA algorithms (Section 3.3.4, 3.3.5)
    'ecdsa-p256-sha256' => Algorithm.new(:ecdsa, 'SHA256', 'prime256v1'),
    'ecdsa-p384-sha384' => Algorithm.new(:ecdsa, 'SHA384', 'secp384r1'),
    # EdDSA algorithm (Section 3.3.6)
    'ed25519' => Algorithm.new(:ed25519, nil)
  }.freeze

  # Configure key store used by Rack middleware
  #
  # Example:
  #   HTTPSignature.configure do |config|
  #     config.keys = [{ id: 'key-1', value: 'MySecureKey' }]
  #   end
  def self.configure
    @config ||= Config.new
    yield(@config) if block_given?
    @config
  end

  def self.keys
    @config&.keys
  end

  def self.key(id)
    key = keys&.find { |o| o[:id] == id }
    key&.dig(:value) || (raise SignatureError, "Key with id #{id} could not be found")
  end

  # Create RFC 9421 Signature-Input and Signature headers
  #
  # @return [Hash] { 'Signature-Input' => header, 'Signature' => header }
  def self.create(
    url:,
    method: :get,
    headers: {},
    body: '',
    key:,
    key_id: SecureRandom.hex(8),
    algorithm: DEFAULT_ALGORITHM,
    covered_components: nil,
    created: Time.now.to_i,
    nonce: nil,
    label: DEFAULT_LABEL,
    query_string_params: {}
  )
    algorithm_entry = algorithm_entry_for(algorithm)
    normalized_headers = normalize_headers(headers)
    uri = apply_query_params(URI(url), query_string_params)

    normalized_headers = ensure_content_digest(normalized_headers, body)

    components =
      covered_components || default_components(normalized_headers)

    canonical_components = build_components(
      uri: uri,
      method: method,
      headers: normalized_headers,
      covered_components: components
    )

    signature_input_header, base_string = build_signature_input(
      label: label,
      components: components,
      created: created,
      key_id: key_id,
      alg: algorithm,
      nonce: nonce,
      canonical_components: canonical_components
    )

    signature_bytes = sign(base_string, key: key, algorithm: algorithm_entry)
    signature_header = build_signature_header(label, signature_bytes)

    {
      'Signature-Input' => signature_input_header,
      'Signature' => signature_header
    }
  end

  # Verify RFC 9421 Signature headers
  #
  # @return [Boolean]
  def self.valid?(
    url:,
    method:,
    headers: {},
    body: '',
    key: nil,
    key_resolver: nil,
    label: DEFAULT_LABEL,
    query_string_params: {}
  )
    normalized_headers = normalize_headers(headers)

    signature_input_header = normalized_headers['signature-input']
    signature_header = normalized_headers['signature']
    raise SignatureError, 'Signature headers are required for verification' unless signature_input_header && signature_header

    parsed_input = parse_signature_input(signature_input_header, label)
    parsed_signature = parse_signature(signature_header, label)

    algorithm_entry = algorithm_entry_for(parsed_input[:params][:alg] || DEFAULT_ALGORITHM)
    key_id = parsed_input[:params][:keyid]
    resolved_key = key || key_resolver&.call(key_id) || key_from_store(key_id)
    raise SignatureError, 'Key is required for verification' unless resolved_key

    uri = apply_query_params(URI(url), query_string_params)
    normalized_headers = ensure_content_digest(normalized_headers, body)

    canonical_components = build_components(
      uri: uri,
      method: method,
      headers: normalized_headers,
      covered_components: parsed_input[:components]
    )

    _, base_string = build_signature_input(
      label: label,
      components: parsed_input[:components],
      created: parsed_input[:params][:created].to_i,
      key_id: key_id,
      alg: parsed_input[:params][:alg],
      nonce: parsed_input[:params][:nonce],
      canonical_components: canonical_components
    )

    verify_signature(base_string, parsed_signature, resolved_key, algorithm_entry)
  end

  # -- Private-ish helpers --

  def self.normalize_headers(headers)
    headers.to_h.transform_keys { |k| k.to_s.downcase }.transform_values(&:to_s)
  end

  def self.apply_query_params(uri, query_string_params)
    return uri if query_string_params.nil? || query_string_params.empty?

    new_uri = uri.dup
    encoded = URI.encode_www_form(query_string_params)
    new_uri.query =
      [new_uri.query, encoded].compact.reject(&:empty?).join('&')
    new_uri
  end

  def self.default_components(headers)
    components = DEFAULT_COMPONENTS.dup
    components << 'date' if headers['date']
    components << 'content-digest' if headers['content-digest']
    components
  end

  def self.ensure_content_digest(headers, body)
    return headers if body.to_s.empty?
    return headers if headers['content-digest']

    digest = Digest::SHA256.digest(body)
    headers.merge('content-digest' => "sha-256=:#{Base64.strict_encode64(digest)}:")
  end

  def self.build_components(uri:, method:, headers:, covered_components:)
    covered_components.map do |component|
      if component.start_with?('@')
        [component, derived_component(component, uri, method)]
      else
        value = headers[component]
        raise MissingComponent, "Missing required component: #{component}" unless value

        [component, canonical_header_value(value)]
      end
    end
  end

  def self.derived_component(component, uri, method)
    case component
    when '@method' then method.to_s.upcase
    when '@authority'
      port = uri.port
      default_port = (uri.scheme == 'https' ? 443 : 80)
      uri.port && port != default_port ? "#{uri.host}:#{uri.port}" : uri.host
    when '@target-uri'
      uri.dup.tap { |u| u.fragment = nil }.to_s
    when '@scheme' then uri.scheme
    when '@path' then uri.path
    when '@query' then uri.query.to_s
    else
      raise MissingComponent, "Unsupported derived component: #{component}"
    end
  end

  def self.canonical_header_value(value)
    value.is_a?(Array) ? value.join(', ') : value.to_s
  end

  def self.build_signature_input(
    label:,
    components:,
    created:,
    key_id:,
    alg:,
    nonce:,
    canonical_components:
  )
    component_tokens = components.map { |c| %("#{c}") }.join(' ')
    params = ["created=#{created}", %(keyid="#{key_id}")]
    params << %(alg="#{alg}") if alg
    params << %(nonce="#{nonce}") if nonce

    signature_params = "(#{component_tokens});#{params.join(';')}"
    signature_input_header = "#{label}=#{signature_params}"

    base_lines = canonical_components.map do |name, value|
      %("#{name}": #{value})
    end
    base_lines << %("@signature-params": #{signature_params})

    [signature_input_header, base_lines.join("\n")]
  end

  def self.build_signature_header(label, signature_bytes)
    "#{label}=:#{Base64.strict_encode64(signature_bytes)}:"
  end

  def self.algorithm_entry_for(algorithm)
    ALGORITHMS[algorithm] || raise(UnsupportedAlgorithm, "Unsupported algorithm #{algorithm}")
  end

  def self.build_digest(algorithm)
    return unless algorithm.digest_name

    OpenSSL::Digest.new(algorithm.digest_name)
  end

  def self.sign(base_string, key:, algorithm:)
    case algorithm.type
    when :hmac
      OpenSSL::HMAC.digest(algorithm.digest_name, key, base_string)
    when :rsa_pss
      pkey = rsa_key(key)
      # Use generic sign with RSA-PSS options (works with all key types)
      digest = build_digest(algorithm)
      pkey.sign(digest, base_string,
        rsa_padding_mode: 'pss',
        rsa_pss_saltlen: -1,
        rsa_mgf1_md: algorithm.digest_name)
    when :rsa
      rsa_key(key).sign(build_digest(algorithm), base_string)
    when :ecdsa
      ec_key = ec_key(key)
      digest = build_digest(algorithm)
      der_signature = ec_key.sign(digest, base_string)
      ecdsa_der_to_raw(der_signature, algorithm.curve)
    when :ed25519
      ed25519_key(key).sign(nil, base_string)
    else
      raise UnsupportedAlgorithm, "Unsupported algorithm #{algorithm}"
    end
  end

  def self.verify_signature(base_string, signature_bytes, key, algorithm)
    case algorithm.type
    when :hmac
      expected = OpenSSL::HMAC.digest(algorithm.digest_name, key, base_string)
      ::Rack::Utils.secure_compare(expected, signature_bytes)
    when :rsa_pss
      pkey = rsa_key(key)
      # Use generic verify with RSA-PSS options (works with all key types)
      digest = build_digest(algorithm)
      pkey.verify(digest, signature_bytes, base_string,
        rsa_padding_mode: 'pss',
        rsa_pss_saltlen: -1,
        rsa_mgf1_md: algorithm.digest_name)
    when :rsa
      rsa_key(key).verify(build_digest(algorithm), signature_bytes, base_string)
    when :ecdsa
      ec_key = ec_key(key)
      der_signature = ecdsa_raw_to_der(signature_bytes, algorithm.curve)
      digest = build_digest(algorithm)
      ec_key.verify(digest, der_signature, base_string)
    when :ed25519
      ed25519_key(key).verify(nil, signature_bytes, base_string)
    else
      false
    end
  end

  def self.parse_signature_input(header, label)
    entry = split_header(header).find { |v| v.start_with?("#{label}=") }
    raise SignatureError, 'Signature-Input missing' unless entry

    components_match = entry.match(/\((.*?)\)/)
    components =
      components_match ? components_match[1].scan(/\"([^\"]+)\"/).flatten : []

    params = entry.split(');').last&.split(';')&.map do |p|
      key, value = p.split('=', 2)
      [key.to_sym, value&.tr('"', '')]
    end.to_h || {}

    { components: components, params: params }
  end

  def self.parse_signature(header, label)
    entry = split_header(header).find { |v| v.start_with?("#{label}=") }
    raise SignatureError, 'Signature missing' unless entry

    encoded = entry.match(/:(.*):/)[1]
    Base64.strict_decode64(encoded)
  end

  def self.split_header(header)
    header.to_s.split(/,(?=[^,]+=)/).map(&:strip)
  end

  def self.key_from_store(key_id)
    return unless keys && key_id

    key(key_id)
  end

  def self.rsa_key(key)
    return key if key.is_a?(OpenSSL::PKey::RSA) || key.is_a?(OpenSSL::PKey::PKey)

    OpenSSL::PKey.read(key)
  end

  def self.ec_key(key)
    key.is_a?(OpenSSL::PKey::EC) ? key : OpenSSL::PKey::EC.new(key)
  end

  def self.ed25519_key(key)
    return key if key.is_a?(OpenSSL::PKey::PKey)

    OpenSSL::PKey.read(key)
  end

  # Convert ECDSA DER signature to raw (r || s) format per RFC 9421
  def self.ecdsa_der_to_raw(der_signature, curve)
    byte_size = curve == 'prime256v1' ? 32 : 48

    asn1 = OpenSSL::ASN1.decode(der_signature)
    r = asn1.value[0].value.to_s(2)
    s = asn1.value[1].value.to_s(2)

    r = r.rjust(byte_size, "\x00")[-byte_size, byte_size]
    s = s.rjust(byte_size, "\x00")[-byte_size, byte_size]

    r + s
  end

  # Convert raw (r || s) signature to ECDSA DER format
  def self.ecdsa_raw_to_der(raw_signature, curve)
    byte_size = curve == 'prime256v1' ? 32 : 48

    r_bytes = raw_signature[0, byte_size]
    s_bytes = raw_signature[byte_size, byte_size]

    r = OpenSSL::BN.new(r_bytes, 2)
    s = OpenSSL::BN.new(s_bytes, 2)

    OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Integer.new(r),
      OpenSSL::ASN1::Integer.new(s)
    ]).to_der
  end
end
