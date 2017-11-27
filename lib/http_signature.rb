# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'time'
require 'base64'
require 'uri'

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
  def self.create(url:, query_string_params: {}, body: '', headers: {}, key:,
    key_id: SecureRandom.hex(8),
    method: :get,
    algorithm: 'hmac-sha256'
  )

    raise 'Unsupported algorithm :(' unless supported_algorithms.include?(algorithm)

    uri = URI(url)
    path = uri.path
    headers = add_date(headers)
    headers = add_digest(headers, body)
    headers = convert_headers(headers)
    # When query string params is also set on the url, append the params defined
    # from `query_string_params`
    query =
      if uri.query || !query_string_params.empty?
        delimiter = uri.query.nil? ? '' : '&'
        '?' + (query_string_params.empty? ? '' : [uri.query.to_s, delimiter, URI.encode_www_form(query_string_params)].join)
      end

    string_to_sign = create_signing_string(method: method, path: path,
      query: query, host: uri.host, headers: headers)

    signature = sign(string_to_sign, key: key, algorithm: algorithm)
    create_signature_header(key_id: key_id, headers: headers, signature: signature,
      algorithm: algorithm)
  end

  def self.sign(string, key:, algorithm:)
    case algorithm
    when 'hmac-sha256'
      OpenSSL::HMAC.hexdigest('SHA256', key, string)
    when 'hmac-sha512'
      OpenSSL::HMAC.hexdigest('SHA512', key, string)
    when 'rsa-sha256'
      k = OpenSSL::PKey::RSA.new(key)
      k.sign(OpenSSL::Digest::SHA256.new, string)
    end
  end

  def self.create_signature_header(key_id:, headers: [], signature:, algorithm:)
    headers = headers.map { |h| h.split(':').first }
    header_fields = ['(request-target)', 'host'].concat(headers).join(' ')

    [
      "keyId=\"#{key_id}\"",
      "algorithm=\"#{algorithm}\"",
      "headers=\"#{header_fields}\"",
      "signature=\"#{Base64.strict_encode64(signature)}\""
    ].join(',')
  end

  # TODO: Support them all: rsa-sha1, rsa-sha512, dsa-sha1, hmac-sha1
  def self.supported_algorithms
    ['hmac-sha256', 'hmac-sha512', 'rsa-sha256']
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
  def self.create_signing_string(method:, path:, query:, host:, headers:)
    [
      "(request-target): #{method} #{path}#{query}",
      "host: #{host}",
    ].concat(headers).join("\n")
  end

  private
    # Convert a header hash into an array with header strings
    # { header: 'value'} -> ['header: value']
    def self.convert_headers(headers)
      headers.map do |key, value|
        [key, value].join(': ')
      end
    end

    def self.add_date(headers)
      headers[:date] = Time.now.httpdate unless headers[:date]

      headers
    end

    def self.add_digest(headers, body)
      headers[:digest] = create_digest(body) unless body.empty?

      headers
    end
end
