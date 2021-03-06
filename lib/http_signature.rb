# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'base64'
require 'uri'

# Implements signing of a request according to https://tools.ietf.org/html/draft-cavage-http-signatures
# specification.
module HTTPSignature
  # Create signature based on the data sent in
  #
  # @param url [String] Full request url, can include query string as well
  # @param query_string_params [Hash] Query string parameters, appends params to
  # url if query string is already found in it
  # @param body [String] Request body as a string, i.e., the "raw" request body
  # @param headers [Hash] Request headers to include in the signature
  # @param key [String] Key/secret that is used by the corresponding `algorithm`
  # @param key_id [String] Key id
  # @param method [Symbol] Request method, default is `:get`
  # @param algorithm [String] Algorithm to use when signing, check `supported_algorithms` for
  # @return [String] The signature header value to use in "Signature" header
  def self.create(
    url:, query_string_params: {}, body: '', headers: {}, key:, key_id: SecureRandom.hex(8),
    method: :get, algorithm: 'hmac-sha256'
  )
    raise 'Unsupported algorithm :(' unless supported_algorithms.include?(algorithm)

    uri = URI(url)
    path = uri.path
    headers = add_digest(headers, body)
    headers = convert_headers(headers)
    query = create_query_string(uri, query_string_params)

    sign_string = create_signing_string(method: method, path: path, query: query, headers: headers)
    signature = sign(sign_string, key: key, algorithm: algorithm)
    create_signature_header(
      key_id: key_id, headers: headers, signature: signature, algorithm: algorithm
    )
  end

  def self.sign(string, key:, algorithm:)
    case algorithm
    when 'hmac-sha256'
      OpenSSL::HMAC.digest('SHA256', key, string)
    when 'hmac-sha512'
      OpenSSL::HMAC.digest('SHA512', key, string)
    when 'rsa-sha256'
      k = OpenSSL::PKey::RSA.new(key)
      k.sign(OpenSSL::Digest::SHA256.new, string)
    when 'rsa-sha512'
      k = OpenSSL::PKey::RSA.new(key)
      k.sign(OpenSSL::Digest::SHA512.new, string)
    end
  end

  def self.create_signature_header(key_id:, headers: [], signature:, algorithm:)
    headers = headers.map { |h| h.split(':').first }
    header_fields = ['(request-target)'].concat(headers).join(' ')

    [
      "keyId=\"#{key_id}\"",
      "algorithm=\"#{algorithm}\"",
      "headers=\"#{header_fields}\"",
      "signature=\"#{Base64.strict_encode64(signature)}\""
    ].join(',')
  end

  # TODO: Support them all: rsa-sha1, rsa-sha512, dsa-sha1, hmac-sha1
  def self.supported_algorithms
    ['hmac-sha256', 'hmac-sha512', 'rsa-sha256', 'rsa-sha512']
  end

  # Create the digest header based on the request body
  # @param body [String] Raw request body string
  # @return [String] SHA256 and base64 digested string with prefix: 'SHA-256='
  def self.create_digest(body)
    'SHA-256=' + Digest::SHA256.base64digest(body)
  end

  # Creates the string to sign
  # See details here: https://tools.ietf.org/html/draft-cavage-http-signatures-08#section-2.3
  # TODO: Concatenate multiple instances of the same headers
  # Also remove leading and trailing whitespace
  # @return [String]
  def self.create_signing_string(method:, path:, query:, headers:)
    [
      "(request-target): #{method.downcase} #{path}#{query}"
    ].concat(headers).join("\n")
  end

  # Check if signature is valid. Using the exact same parameters as .create
  # minus `key_id`
  #
  # @param url [String] Full request url, can include query string as well
  # @param query_string_params [Hash] Query string parameters, appends params to
  # url if query string is already found in it
  # @param body [String] Request body as a string, i.e., the "raw" request body
  # @param headers [Hash] Request headers to include in the signature
  # @param key [String] Key/secret that is used by the corresponding `algorithm`
  # @param method [Symbol] Request method, default is `:get`
  # @param algorithm [String] Algorithm to use when signing, check `supported_algorithms` for
  # @return [Boolean] Valid or not, Crypto is kinda binary in this case :)
  def self.valid?(url:, query_string_params: {}, body: '', headers: {}, key:, method:, algorithm:)
    raise 'Key needs to be public' unless key.public?

    # TODO: A lot of the code here is exactly as `.create`, i.e., this could be DRYed :point_down:
    uri = URI(url)
    path = uri.path
    signature = headers.delete(:signature)
    headers = add_digest(headers, body)
    headers = convert_headers(headers)
    query = create_query_string(uri, query_string_params)

    string_to_sign = create_signing_string(
      method: method, path: path, query: query, headers: headers
    )

    key.verify(
      get_digest(algorithm), get_signature_from_header(signature), string_to_sign
    )
  end

  # Maps algoritgm string to digest object
  # @param algorithm [String]
  # @return [OpenSSL::Digest] Instance of `OpenSSL::Digest::SHA256` or OpenSSL::Digest::SHA512
  def self.get_digest(algorithm)
    {
      'rsa-sha256' => OpenSSL::Digest::SHA256.new,
      'rsa-sha512' => OpenSSL::Digest::SHA512.new
    }[algorithm]
  end

  # Extract the actual signature from the whole "Signature" header
  # @param header [String]
  # @return [String]
  def self.get_signature_from_header(header)
    Base64.strict_decode64(header.match(/signature\=\"(.*)\"/)[1])
  end

  # When query string params is also set on the url, append the params defined
  # in `query_string_params` and make a joint query string
  def self.create_query_string(uri, query_string_params)
    return if !uri.query && query_string_params.empty?

    delimiter = uri.query.nil? || query_string_params.empty? ? '' : '&'

    ['?', uri.query.to_s, delimiter, URI.encode_www_form(query_string_params)].join
  end

  # Convert a header hash into an array with header strings
  # { header: 'value'} -> ['header: value']
  def self.convert_headers(headers)
    headers.map do |key, value|
      [key.to_s.downcase.strip, value.strip].join(': ')
    end
  end

  def self.add_digest(headers, body)
    headers[:digest] = create_digest(body) unless body.empty?
    headers
  end

  def self.config(**options)
    @keys = options[:keys]
  end

  def self.key(id)
    key = @keys.select { |o| o[:id] == id }.first

    key&.dig(:value) || (raise "Key with id #{id} could not be found")
  end

  class << self
    attr_reader :keys
  end
end
