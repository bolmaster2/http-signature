# frozen_string_literal: true

require 'minitest/autorun'
require './lib/http_signature'

describe HTTPSignature do
  def hmac_key
    'secret-key'
  end

  describe '.create and .valid?' do
    it 'creates headers and validates with hmac-sha256' do
      headers = { 'date' => 'Tue, 20 Apr 2021 02:07:55 GMT' }
      url = 'https://example.com/foo?pet=dog'

      sig_headers = HTTPSignature.create(
        url: url,
        method: :get,
        headers: headers,
        key_id: 'test',
        key: hmac_key,
        covered_components: %w[@method @authority @target-uri date],
        created: 1_618_884_473
      )

      assert sig_headers['Signature-Input']
      assert sig_headers['Signature']

      assert HTTPSignature.valid?(
        url: url,
        method: :get,
        headers: headers,
        key: hmac_key,
        signature_input_header: sig_headers['Signature-Input'],
        signature_header: sig_headers['Signature']
      )
    end

    it 'adds content-digest when body is present' do
      body = '{"hello":"world"}'
      headers = {}
      url = 'https://example.com/submit'

      sig_headers = HTTPSignature.create(
        url: url,
        method: :post,
        headers: headers,
        body: body,
        key_id: 'test',
        key: hmac_key
      )

      assert_includes sig_headers['Signature-Input'], 'content-digest'
    end

    it 'raises when a required header component is missing' do
      assert_raises(HTTPSignature::MissingComponent) do
        HTTPSignature.create(
          url: 'https://example.com/test',
          method: :get,
          headers: {},
          key: hmac_key,
          covered_components: %w[date]
        )
      end
    end
  end

end
