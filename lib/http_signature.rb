# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'base64'
require 'uri'
require 'digest'
require 'rack/utils'

# Implements HTTP Message Signatures per RFC 9421.
module HTTPSignature
  DEFAULT_LABEL = 'sig1'
  DEFAULT_ALGORITHM = 'hmac-sha256'
  DEFAULT_COMPONENTS = %w[@method @authority @target-uri].freeze

  class SignatureError < StandardError; end
  class MissingComponent < SignatureError; end
  class UnsupportedAlgorithm < SignatureError; end

  Algorithm = Struct.new(:type, :digest, :openssl_digest)
  ALGORITHMS = {
    'hmac-sha256' => Algorithm.new(:hmac, 'SHA256', OpenSSL::Digest::SHA256.new),
    'hmac-sha512' => Algorithm.new(:hmac, 'SHA512', OpenSSL::Digest::SHA512.new),
    'rsa-pss-sha256' => Algorithm.new(:rsa_pss, 'SHA256', OpenSSL::Digest::SHA256.new),
    'rsa-pss-sha512' => Algorithm.new(:rsa_pss, 'SHA512', OpenSSL::Digest::SHA512.new),
    # Kept for compatibility if callers request pkcs#1 directly
    'rsa-sha256' => Algorithm.new(:rsa, 'SHA256', OpenSSL::Digest::SHA256.new),
    'rsa-sha512' => Algorithm.new(:rsa, 'SHA512', OpenSSL::Digest::SHA512.new)
  }.freeze

  class << self
    attr_reader :keys
  end

  # Configure key store used by Rack middleware
  def self.config(**options)
    @keys = options[:keys]
  end

  def self.key(id)
    key = @keys.select { |o| o[:id] == id }.first
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
    signature_input_header:,
    signature_header:,
    query_string_params: {}
  )
    parsed_input = parse_signature_input(signature_input_header, label)
    parsed_signature = parse_signature(signature_header, label)

    algorithm_entry = algorithm_entry_for(parsed_input[:params][:alg] || DEFAULT_ALGORITHM)
    key_id = parsed_input[:params][:keyid]
    resolved_key = key || key_resolver&.call(key_id) || key_from_store(key_id)
    raise SignatureError, 'Key is required for verification' unless resolved_key

    uri = apply_query_params(URI(url), query_string_params)
    normalized_headers = normalize_headers(headers)
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

  def self.sign(base_string, key:, algorithm:)
    case algorithm.type
    when :hmac
      OpenSSL::HMAC.digest(algorithm.digest, key, base_string)
    when :rsa_pss
      rsa_key(key).sign_pss(
        algorithm.openssl_digest,
        base_string,
        salt_length: :max,
        mgf1_hash: algorithm.openssl_digest
      )
    when :rsa
      rsa_key(key).sign(algorithm.openssl_digest, base_string)
    else
      raise UnsupportedAlgorithm, "Unsupported algorithm #{algorithm}"
    end
  end

  def self.verify_signature(base_string, signature_bytes, key, algorithm)
    case algorithm.type
    when :hmac
      expected = OpenSSL::HMAC.digest(algorithm.digest, key, base_string)
      ::Rack::Utils.secure_compare(expected, signature_bytes)
    when :rsa_pss
      rsa_key(key).verify_pss(
        algorithm.openssl_digest,
        signature_bytes,
        base_string,
        salt_length: :max,
        mgf1_hash: algorithm.openssl_digest
      )
    when :rsa
      rsa_key(key).verify(algorithm.openssl_digest, signature_bytes, base_string)
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
    return unless defined?(@keys) && @keys

    key(key_id) if key_id
  end

  def self.rsa_key(key)
    key.is_a?(OpenSSL::PKey::RSA) ? key : OpenSSL::PKey::RSA.new(key)
  end
end
