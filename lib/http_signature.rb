# frozen_string_literal: true

require "openssl"
require "base64"
require "uri"
require "digest"
require "starry"

# Implements HTTP Message Signatures per RFC 9421.
module HTTPSignature
  Config = Struct.new(:keys)
  DEFAULT_LABEL = "sig1"
  DEFAULT_ALGORITHM = "hmac-sha256"
  DEFAULT_COMPONENTS = %w[@method @target-uri].freeze
  DEFAULT_HEADERS = %w[content-digest content-type].freeze

  class SignatureError < StandardError; end
  class MissingComponent < SignatureError; end
  class UnsupportedComponent < SignatureError; end
  class UnsupportedAlgorithm < SignatureError; end
  class ExpiredError < SignatureError; end

  SUPPORTED_DERIVED_COMPONENTS = %w[@method @authority @target-uri @request-target @scheme @path @query @query-param @status].freeze

  Algorithm = Struct.new(:type, :digest_name, :curve)
  ALGORITHMS = {
    "hmac-sha256" => Algorithm.new(:hmac, "SHA256"),
    "hmac-sha512" => Algorithm.new(:hmac, "SHA512"),
    "rsa-pss-sha256" => Algorithm.new(:rsa_pss, "SHA256"),
    "rsa-pss-sha512" => Algorithm.new(:rsa_pss, "SHA512"),
    "rsa-v1_5-sha256" => Algorithm.new(:rsa, "SHA256"),
    "ecdsa-p256-sha256" => Algorithm.new(:ecdsa, "SHA256", "prime256v1"),
    "ecdsa-p384-sha384" => Algorithm.new(:ecdsa, "SHA384", "secp384r1"),
    "ed25519" => Algorithm.new(:ed25519, nil)
  }.freeze

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
  # @param url [String] The full URL of the request being signed
  # @param key [String, OpenSSL::PKey::PKey] The signing key (secret for HMAC, private key for asymmetric)
  # @param key_id [String] Identifier for the key, included in the signature metadata
  # @param method [Symbol] HTTP method (default: :get)
  # @param headers [Hash] Request headers to potentially include in signature (default: {})
  # @param body [String] Request body, used to generate content-digest if needed (default: "")
  # @param algorithm [String] Signing algorithm (default: "hmac-sha256")
  # @param components [Array<String>, nil] Components to sign. If nil, uses @method, @target-uri,
  #   and includes content-digest/content-type when present
  # @param created [Integer] Unix timestamp for signature creation (default: Time.now.to_i)
  # @param expires [Integer, nil] Unix timestamp when signature expires (default: nil)
  # @param nonce [String, nil] Random value for signature uniqueness (default: nil)
  # @param tag [String, nil] Application-specific tag parameter included in signature metadata (default: nil)
  # @param label [String] Signature label in headers (default: "sig1")
  # @param query_string_params [Hash] Additional query params to merge into URL (default: {})
  # @param include_alg [Boolean] Whether to include alg in signature metadata (default: true)
  # @param status [Integer, nil] HTTP status code, required when signing responses with @status component
  # @return [Hash] { 'Signature-Input' => header, 'Signature' => header }
  # @raise [ArgumentError] If created/expires are not integers or expires < created
  # @raise [UnsupportedAlgorithm] If the algorithm is not supported
  # @raise [UnsupportedComponent] If a derived component (e.g. @foo) is not supported
  # @raise [MissingComponent] If a required component is missing
  def self.create(
    url:,
    key:,
    key_id:,
    method: :get,
    headers: {},
    body: "",
    algorithm: DEFAULT_ALGORITHM,
    components: nil,
    created: Time.now.to_i,
    expires: nil,
    nonce: nil,
    tag: nil,
    label: DEFAULT_LABEL,
    query_string_params: {},
    include_alg: true,
    status: nil,
    attached_request: nil
  )
    unless created.is_a?(Integer)
      raise ArgumentError, "created must be a Unix timestamp integer"
    end
    if expires && !expires.is_a?(Integer)
      raise ArgumentError, "expires must be a Unix timestamp integer"
    end
    if expires && created > expires
      raise ArgumentError, "expires (#{expires}) must be greater than created (#{created})"
    end
    algorithm_entry = algorithm_entry_for(algorithm)
    normalized_headers = normalize_headers(headers)
    uri = apply_query_params(URI(url), query_string_params)

    components ||=
      default_components(normalized_headers, body:)

    validate_components!(components)

    had_content_digest = normalized_headers.key?("content-digest")

    normalized_headers =
      if components.include?("content-digest")
        ensure_content_digest(normalized_headers, body)
      else
        normalized_headers
      end

    normalized_attached = attached_request ? {headers: normalize_headers(attached_request[:headers])} : nil

    canonical_components = build_components(
      uri:,
      method:,
      headers: normalized_headers,
      components:,
      status:,
      attached_request: normalized_attached
    )

    signature_input_header, base_string = build_signature_input(
      label:,
      components:,
      created:,
      expires:,
      key_id:,
      alg: include_alg ? algorithm : nil,
      nonce:,
      tag:,
      canonical_components:
    )

    signature_bytes = sign(base_string, key: key, algorithm: algorithm_entry)
    signature_header = build_signature_header(label, signature_bytes)

    result = {
      "Signature-Input" => signature_input_header,
      "Signature" => signature_header
    }

    if !had_content_digest && normalized_headers["content-digest"]
      result["Content-Digest"] = normalized_headers["content-digest"]
    end

    result
  end

  # Verify RFC 9421 Signature headers
  #
  # @param url [String] The full URL of the request being verified
  # @param method [Symbol] HTTP method of the request
  # @param headers [Hash] Request headers, must include Signature-Input and Signature headers
  # @param body [String] Request body (default: "")
  # @param key [String, OpenSSL::PKey::PKey, nil] Verification key. If nil, uses key_resolver or configured keys
  # @param key_resolver [Proc, nil] Callable that receives key_id and returns the key (default: nil)
  # @param label [String, nil] Signature label to verify. If nil, auto-detects
  #   the first label from the Signature-Input header (default: nil)
  # @param query_string_params [Hash] Additional query params to merge into URL (default: {})
  # @param max_age [Integer, nil] Maximum signature age in seconds. Takes precedence over
  #   the expires timestamp in the signature (default: nil)
  # @param algorithm [String, nil] Override algorithm for verification. If nil, uses alg from
  #   signature params or defaults to hmac-sha256 (default: nil)
  # @param status [Integer, nil] HTTP status code, required when verifying responses with @status component
  # @param require_content_digest [Boolean] When true, raises if a body is present but content-digest
  #   is not in the signed components. Useful for enforcing body integrity (default: false)
  # @return [Boolean] true when signature verification succeeds
  # @raise [ArgumentError] If max_age is not a non-negative integer
  # @raise [SignatureError] If signature headers are missing, key is missing, or signature is invalid
  # @raise [ExpiredError] If the signature has expired
  def self.valid?(
    url:,
    method:,
    headers: {},
    body: "",
    key: nil,
    key_resolver: nil,
    label: nil,
    query_string_params: {},
    max_age: nil,
    algorithm: nil,
    status: nil,
    require_content_digest: false,
    attached_request: nil
  )
    if max_age && (!max_age.is_a?(Integer) || max_age < 0)
      raise ArgumentError, "max_age must be a non-negative integer"
    end
    normalized_headers = normalize_headers(headers)

    signature_input_header = normalized_headers["signature-input"]
    signature_header = normalized_headers["signature"]
    raise SignatureError, "Signature headers are required for verification" unless signature_input_header && signature_header

    label ||= detect_label(signature_input_header)

    parsed_input = parse_signature_input(signature_input_header, label)
    validate_components!(parsed_input[:components])
    parsed_signature = parse_signature(signature_header, label)

    algorithm_entry = algorithm_entry_for(algorithm || parsed_input[:params][:alg] || DEFAULT_ALGORITHM)
    key_id = parsed_input[:params][:keyid]
    created = parse_signature_timestamp(parsed_input[:params][:created], :created)
    signature_expires = parse_signature_timestamp(parsed_input[:params][:expires], :expires, required: false)
    effective_expires = max_age ? created + max_age : signature_expires
    now = Time.now.to_i
    if effective_expires && (created > effective_expires || now > effective_expires)
      raise ExpiredError, "Signature expired at #{effective_expires}"
    end
    resolved_key = key || key_resolver&.call(key_id) || key_from_store(key_id)
    raise SignatureError, "Key is required for verification" unless resolved_key

    uri = apply_query_params(URI(url), query_string_params)
    if require_content_digest && !body.to_s.empty? && !parsed_input[:components].include?("content-digest")
      raise SignatureError, "content-digest component is required when body is present"
    end

    if parsed_input[:components].include?("content-digest")
      unless normalized_headers["content-digest"]
        raise MissingComponent, "Missing required component: content-digest"
      end
      verify_content_digest!(normalized_headers["content-digest"], body) unless body.to_s.empty?
    end

    normalized_attached = attached_request ? {headers: normalize_headers(attached_request[:headers])} : nil

    canonical_components = build_components(
      uri:,
      method:,
      headers: normalized_headers,
      components: parsed_input[:components],
      status:,
      attached_request: normalized_attached
    )

    _, base_string = build_signature_input(
      label:,
      components: parsed_input[:components],
      created:,
      expires: signature_expires,
      key_id:,
      alg: parsed_input[:params][:alg],
      nonce: parsed_input[:params][:nonce],
      tag: parsed_input[:params][:tag],
      canonical_components:
    )

    verified = verify_signature(base_string, parsed_signature, resolved_key, algorithm_entry)
    raise SignatureError, "Invalid signature" unless verified

    true
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
      [new_uri.query, encoded].compact.reject(&:empty?).join("&")
    new_uri
  end

  KNOWN_PARAMETERS = %w[sf key bs req tr name].freeze

  def self.validate_components!(components)
    if components.include?("@signature-params")
      raise UnsupportedComponent, "@signature-params cannot be included as a component"
    end

    seen = {}
    components.each do |component|
      if seen[component]
        raise UnsupportedComponent, "Duplicate component: #{component}"
      end
      seen[component] = true

      params = parse_component_params(component)
      has_sf = params["sf"] || params.key?("key")
      has_bs = params["bs"]

      if has_sf && has_bs
        raise UnsupportedComponent, "Cannot combine ;sf/;key with ;bs: #{component}"
      end

      if params.key?("name") && !component.start_with?("@query-param")
        raise UnsupportedComponent, ";name parameter only valid with @query-param: #{component}"
      end

      next unless component.start_with?("@")
      base = component.split(";").first
      next if SUPPORTED_DERIVED_COMPONENTS.include?(base)

      raise UnsupportedComponent, "Unsupported component: #{component}"
    end
  end

  def self.parse_component_params(component)
    _, raw_params = component.split(";", 2)
    return {} unless raw_params

    raw_params.split(";").each_with_object({}) do |param, hash|
      key, value = param.split("=", 2)
      hash[key] = value ? value.delete_prefix('"').delete_suffix('"') : true
    end
  end

  def self.default_components(headers, body: nil)
    components = DEFAULT_COMPONENTS.dup
    DEFAULT_HEADERS.each do |header|
      include_header =
        if header == "content-digest"
          !body.to_s.empty? || headers[header]
        else
          headers[header]
        end

      components << header if include_header
    end

    components
  end

  def self.ensure_content_digest(headers, body)
    return headers if body.to_s.empty?

    if headers["content-digest"]
      verify_content_digest!(headers["content-digest"], body)
      return headers
    end

    digest = Digest::SHA256.digest(body)
    headers.merge("content-digest" => "sha-256=:#{Base64.strict_encode64(digest)}:")
  end

  def self.verify_content_digest!(header_value, body)
    verified = false

    split_header(header_value).each do |entry|
      alg, digest_value = entry.split("=", 2)
      next unless alg && digest_value&.start_with?(":") && digest_value.end_with?(":")

      encoded_digest = digest_value[1...-1]
      digest = case alg
      when "sha-256" then Digest::SHA256.digest(body)
      when "sha-512" then Digest::SHA512.digest(body)
      end
      next unless digest

      begin
        decoded = Base64.strict_decode64(encoded_digest)
      rescue ArgumentError
        raise SignatureError, "Invalid Content-Digest encoding for #{alg}"
      end
      unless digest == decoded
        raise SignatureError, "Content-Digest mismatch: body does not match #{alg} digest"
      end
      verified = true
    end

    raise SignatureError, "Content-Digest header contains no supported algorithm" unless verified
  end

  def self.build_components(uri:, method:, headers:, components:, status: nil, attached_request: nil)
    components.map do |component|
      params = parse_component_params(component)
      base = component.split(";").first

      if params["req"]
        raise MissingComponent, ";req requires an attached request" unless attached_request
        req_component = component.sub(/;req(?:=\S+)?/, "")
        value = resolve_component_value(req_component, uri, method, attached_request[:headers], status:)
      elsif base.start_with?("@")
        value = derived_component(component, uri, method, status:)
      else
        raw = headers[base]
        raise MissingComponent, "Missing required component: #{base}" unless raw
        value = canonical_header_value(raw)
      end

      value = apply_structured_params(value, params)

      [component, value]
    end
  end

  def self.resolve_component_value(component, uri, method, headers, status: nil)
    base = component.split(";").first
    if base.start_with?("@")
      derived_component(component, uri, method, status:)
    else
      raw = headers[base]
      raise MissingComponent, "Missing required component: #{base}" unless raw
      canonical_header_value(raw)
    end
  end

  def self.apply_structured_params(value, params)
    has_sf = params["sf"] || params.key?("key")
    has_bs = params["bs"]

    if has_sf
      key = params["key"]
      if key
        dict = Starry.parse_dictionary(value)
        obj = dict[key]
        raise MissingComponent, "Dictionary member not found: #{key}" unless obj
        Starry.serialize(obj.is_a?(Starry::InnerList) ? [obj] : obj)
      else
        Starry.serialize(parse_structured_field(value))
      end
    elsif has_bs
      Starry.serialize(value.encode(Encoding::ASCII_8BIT))
    else
      value
    end
  rescue Starry::ParseError
    raise SignatureError, "Failed to parse structured field value"
  end

  def self.parse_structured_field(value)
    Starry.parse_dictionary(value)
  rescue Starry::ParseError
    begin
      Starry.parse_list(value)
    rescue Starry::ParseError
      Starry.parse_item(value)
    end
  end

  def self.derived_component(component, uri, method, status: nil)
    base = component.split(";").first

    case base
    when "@method" then method.to_s.upcase
    when "@authority"
      port = uri.port
      default_port = ((uri.scheme == "https") ? 443 : 80)
      (uri.port && port != default_port) ? "#{uri.host}:#{uri.port}" : uri.host
    when "@target-uri"
      uri.dup.tap { |u| u.fragment = nil }.to_s
    when "@request-target"
      path = uri.path.empty? ? "/" : uri.path
      uri.query ? "#{path}?#{uri.query}" : path
    when "@scheme" then uri.scheme
    when "@path"
      path = uri.path
      path.empty? ? "/" : path
    when "@query" then "?#{uri.query}"
    when "@query-param"
      encoded_name = component.match(/;name="([^"]*)"/)&.[](1)
      raise MissingComponent, "@query-param requires a name parameter" unless encoded_name
      name = URI.decode_www_form_component(encoded_name)
      pair = uri.query.to_s.split("&").map { |p| p.split("=", 2) }.find { |n, _| URI.decode_www_form_component(n) == name }
      raise MissingComponent, "Query parameter not found: #{encoded_name}" unless pair
      pair[1].to_s.tr("+", "%20")
    when "@status"
      raise MissingComponent, "@status requires a status code" unless status
      status.to_s
    else
      raise MissingComponent, "Unsupported derived component: #{component}"
    end
  end

  def self.canonical_header_value(value)
    value.is_a?(Array) ? value.join(", ") : value.to_s
  end

  def self.serialize_component_id(component)
    base, params = component.split(";", 2)
    serialized = %("#{escape_structured_string(base)}")
    serialized << ";#{params}" if params
    serialized
  end

  def self.escape_structured_string(value)
    value.to_s.gsub("\\") { "\\\\" }.gsub('"') { '\"' }
  end

  def self.unescape_structured_string(value)
    return value unless value

    value.delete_prefix('"').delete_suffix('"')
      .gsub('\\"', '"').gsub("\\\\", "\\")
  end

  def self.build_signature_input(
    label:,
    components:,
    created:,
    expires:,
    key_id:,
    alg:,
    nonce:,
    tag:,
    canonical_components:
  )
    component_tokens = components.map { |c| serialize_component_id(c) }.join(" ")
    params = ["created=#{created}"]
    params << "expires=#{expires}" unless expires.nil?
    params << %(keyid="#{escape_structured_string(key_id)}")
    params << %(alg="#{escape_structured_string(alg)}") if alg
    params << %(nonce="#{escape_structured_string(nonce)}") if nonce
    params << %(tag="#{escape_structured_string(tag)}") if tag

    signature_params = "(#{component_tokens});#{params.join(";")}"
    signature_input_header = "#{label}=#{signature_params}"

    base_lines = canonical_components.map do |name, value|
      "#{serialize_component_id(name)}: #{value}"
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
    if algorithm.type == :hmac && asymmetric_key?(key)
      raise SignatureError, "HMAC algorithm cannot be used with an asymmetric key"
    end

    case algorithm.type
    when :hmac
      OpenSSL::HMAC.digest(algorithm.digest_name, key, base_string)
    when :rsa_pss
      pkey = rsa_key(key)
      # Use generic sign with RSA-PSS options (works with all key types)
      digest = build_digest(algorithm)
      pkey.sign(digest, base_string,
        rsa_padding_mode: "pss",
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
    if algorithm.type == :hmac && asymmetric_key?(key)
      raise SignatureError, "HMAC algorithm cannot be used with an asymmetric key"
    end

    case algorithm.type
    when :hmac
      expected = OpenSSL::HMAC.digest(algorithm.digest_name, key, base_string)
      expected.bytesize == signature_bytes.bytesize &&
        OpenSSL.fixed_length_secure_compare(expected, signature_bytes)
    when :rsa_pss
      pkey = rsa_key(key)
      # Use generic verify with RSA-PSS options (works with all key types)
      digest = build_digest(algorithm)
      pkey.verify(digest, signature_bytes, base_string,
        rsa_padding_mode: "pss",
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
    raise SignatureError, "Signature-Input missing" unless entry

    components_match = entry.match(/\((.*?)\)/)
    components = if components_match
      components_match[1].scan(/"([^"]+)"((?:;[a-z]+(?:=(?:"[^"]*"|\S+))?)*)/).map do |base, params|
        params.empty? ? base : "#{base}#{params}"
      end
    else
      []
    end

    params = entry.split(");").last&.split(";")&.map do |p|
      key, value = p.split("=", 2)
      [key.to_sym, unescape_structured_string(value)]
    end.to_h

    {components:, params:}
  end

  def self.parse_signature(header, label)
    entry = split_header(header).find { |v| v.start_with?("#{label}=") }
    raise SignatureError, "Signature missing" unless entry

    match = entry.match(/:(.*):\z/)
    raise SignatureError, "Invalid signature format" unless match

    encoded = match[1]
    Base64.strict_decode64(encoded)
  rescue ArgumentError
    raise SignatureError, "Invalid signature format"
  end

  def self.split_header(header)
    header.to_s.split(/,(?=[^,]+=)/).map(&:strip)
  end

  def self.detect_label(signature_input_header)
    entry = split_header(signature_input_header).first
    raise SignatureError, "Signature-Input missing" unless entry

    label = entry.split("=", 2).first
    raise SignatureError, "Signature-Input missing" if label.nil? || label.empty?

    label
  end

  def self.key_from_store(key_id)
    return unless keys && key_id

    key(key_id)
  end

  def self.parse_signature_timestamp(value, param_name, required: true)
    if value.nil?
      raise SignatureError, "Missing required #{param_name} parameter" if required
      return nil
    end

    unless value.match?(/\A\d+\z/)
      raise SignatureError, "Invalid #{param_name} parameter"
    end

    value.to_i
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

  def self.asymmetric_key?(key)
    return true if key.is_a?(OpenSSL::PKey::PKey)
    return false unless key.is_a?(String)

    pkey = nil

    # Try parsing as an OpenSSL PKey
    # Fast path for PEM encoded keys
    if key.match?(/\A\s*-----BEGIN/)
      begin
        pkey = OpenSSL::PKey.read(key)
      rescue ArgumentError, OpenSSL::PKey::PKeyError
        return false
      end
    # For binary DER, only attempt parse if it looks like ASN.1 SEQUENCE (0x30)
    # to avoid misclassifying raw HMAC secrets that start with 0x30 as asymmetric
    elsif key.bytes[0] == 0x30
      begin
        pkey = OpenSSL::PKey.read(key)
      rescue ArgumentError, OpenSSL::PKey::PKeyError
        return false
      end
    end

    return false unless pkey

    # Only treat as asymmetric if parsed to a known key type with sane structure,
    # so raw binary that parses as arbitrary DER is not misclassified as a key
    case pkey
    when OpenSSL::PKey::RSA
      pkey.n&.num_bits.to_i >= 512
    when OpenSSL::PKey::EC
      true
    else
      # Ed25519 or other PKey subclass
      true
    end
  end

  # Convert ECDSA DER signature to raw (r || s) format per RFC 9421
  def self.ecdsa_der_to_raw(der_signature, curve)
    byte_size = (curve == "prime256v1") ? 32 : 48

    asn1 = OpenSSL::ASN1.decode(der_signature)
    r = asn1.value[0].value.to_s(2)
    s = asn1.value[1].value.to_s(2)

    r = r.rjust(byte_size, "\x00")[-byte_size, byte_size]
    s = s.rjust(byte_size, "\x00")[-byte_size, byte_size]

    r + s
  end

  # Convert raw (r || s) signature to ECDSA DER format
  def self.ecdsa_raw_to_der(raw_signature, curve)
    byte_size = (curve == "prime256v1") ? 32 : 48
    expected_size = byte_size * 2
    unless raw_signature.is_a?(String) && raw_signature.bytesize == expected_size
      raise SignatureError, "Invalid ECDSA signature length"
    end

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
