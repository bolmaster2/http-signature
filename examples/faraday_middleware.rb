# frozen_string_literal: true

require 'http_signature'

class AddRequestSignature < Faraday::Middleware
  def call(env)
    if env[:body]
      env[:request_headers].merge!('Digest' => HTTPSignature.create_digest(env[:body]))
    end

    # Choose which headers to sign
    filtered_headers = %w{ Host Date Digest }
    headers_to_sign = env[:request_headers].select { |k, v| filtered_headers.include?(k.to_s) }

    headers.select { |header| headers_to_sign.includes(header) }.to_h

    signature = HTTPSignature.create(
      url: env[:url],
      method: env[:method],
      headers: headers,
      key: ENV.fetch('REQUEST_SIGNATURE_KEY'),
      key_id: ENV.fetch('REQUEST_SIGNATURE_KEY_ID'),
      algorithm: 'hmac-sha256',
      body: env[:body] ? env[:body] : ''
    )

    env[:request_headers].merge!('Signature' => signature)

    @app.call(env)
  end
end
