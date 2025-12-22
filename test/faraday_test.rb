# frozen_string_literal: true

require 'minitest/autorun'
require './lib/http_signature'
require './lib/http_signature/faraday'
require 'faraday'

describe HTTPSignature::Faraday do
  def hmac_key
    'secret-key'
  end

  it 'adds Signature-Input and Signature headers to outgoing requests' do
    HTTPSignature::Faraday.key = hmac_key
    HTTPSignature::Faraday.key_id = 'key-1'

    captured_env = nil
    conn = Faraday.new('http://example.com') do |faraday|
      faraday.use(HTTPSignature::Faraday)
      faraday.adapter(:test) do |stub|
        stub.get('/') do |env|
          captured_env = env
          [200, {}, 'ok']
        end
      end
    end

    conn.get('/') do |req|
      req.headers['Date'] = 'Tue, 20 Apr 2021 02:07:55 GMT'
      req.headers['Host'] = 'example.com'
    end

    refute_nil captured_env
    assert captured_env[:request_headers]['Signature-Input']
    assert captured_env[:request_headers]['Signature']
  end
end
