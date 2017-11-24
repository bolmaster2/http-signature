require 'openssl'
require 'securerandom'
require 'time'
require 'base64'

module HTTPSignature
  def self.create(url:, params: {}, body: '', headers: {}, key:,
    key_id: SecureRandom.hex(8),
    method: :get,
    algorithm: 'hmac-sha256'
  )

    raise 'Unsupported algorithm :(' unless supported_algorithms.include?(algorithm)

    host = get_host(url)
    path = get_path(url)
    headers = add_date(headers)
    headers = add_digest(headers, body)
    headers = convert_headers(headers)
    query_string = params.empty? ? '' : '?' + URI.encode_www_form(params)

    string_to_sign = [
      "(request-target): #{method} #{path}#{query_string}",
      "host: #{host}",
    ].concat(headers).join("\n")

    signature = sign(string_to_sign, key: key, algorithm: algorithm)
    create_signature_header(key_id: key_id, headers: headers, signature: signature,
      algorithm: algorithm)
  end

  def self.sign(string, key:, algorithm:)
    case algorithm
    when 'hmac-sha256'
      OpenSSL::HMAC.hexdigest('SHA256', key, string)
    when 'rsa-sha256'
      k = OpenSSL::PKey::RSA.new(key)
      k.sign(OpenSSL::Digest::SHA256.new, string)
    end
  end

  def self.get_host(url)
    split_url(url).first
  end

  def self.get_path(url)
    '/' + split_url(url).drop(1).join('/')
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

  # TODO: Support them all: rsa-sha1, rsa-sha512, dsa-sha1, hmac-sha1, hmac-sha512
  def self.supported_algorithms
    ['hmac-sha256', 'rsa-sha256']
  end

  # Create the digest header based on the body
  def self.create_digest(body)
    'SHA-256=' + Digest::SHA256.base64digest(body)
  end

  private
    def self.split_url(url)
      # Removes both http:// and https:// and then slit it into an array by /
      # First value in array is always the hostname
      url.gsub(/^http(|s):\/\//, '').split('/')
    end

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
