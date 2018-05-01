# frozen_string_literal: true

require 'http_signature'
require 'faraday'

class HTTPSignature::Faraday < Faraday::Middleware
  class << self
    attr_accessor :key, :key_id
  end

  def call(env)
    raise 'key and key_id needs to be set' if self.class.key.nil? || self.class.key_id.nil?

    body =
      if env[:body] && env[:body].respond_to?(:read)
        string = env[:body].read
        env[:body].rewind
        string
      else
        env[:body].to_s
      end

    # Choose which headers to sign
    filtered_headers = %w{ Host Date Digest }
    headers_to_sign = env[:request_headers].select { |k, v| filtered_headers.include?(k.to_s) }

    signature = HTTPSignature.create(
      url: env[:url],
      method: env[:method],
      headers: headers_to_sign,
      key: self.class.key,
      key_id: self.class.key_id,
      algorithm: 'hmac-sha256',
      body: body
    )

    env[:request_headers].merge!('Signature' => signature)

    @app.call(env)
  end
end
