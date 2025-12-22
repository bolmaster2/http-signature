# frozen_string_literal: true

require 'minitest/autorun'
require './lib/http_signature'
require './lib/http_signature/rack'
require 'rack/mock'

describe HTTPSignature::Rack do
  def hmac_key
    'secret-key'
  end

  it 'verifies an incoming request with valid signature' do
    HTTPSignature.config(keys: [{ id: 'key-1', value: hmac_key }])
    date = 'Tue, 20 Apr 2021 02:07:55 GMT'
    url = 'http://example.com/hello?pet=dog'

    sig_headers = HTTPSignature.create(
      url: url,
      method: :get,
      headers: { 'date' => date },
      key_id: 'key-1',
      key: hmac_key,
      covered_components: %w[@method @authority @target-uri date],
      created: 1_618_884_473
    )

    app = ->(_env) { [200, { 'Content-Type' => 'text/plain' }, ['ok']] }
    middleware = HTTPSignature::Rack.new(app)
    request = Rack::MockRequest.new(middleware)

    response = request.get(
      '/hello?pet=dog',
      'HTTP_HOST' => 'example.com',
      'HTTP_DATE' => date,
      'HTTP_SIGNATURE_INPUT' => sig_headers['Signature-Input'],
      'HTTP_SIGNATURE' => sig_headers['Signature']
    )

    assert_equal 200, response.status
    assert_equal 'ok', response.body
  end
end
