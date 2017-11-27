# frozen_string_literal: true

require 'minitest/autorun'
require './lib/http_signature'

describe HTTPSignature do
  def public_key
    File.read('test/keys/id_rsa.pub')
  end

  def private_key
    File.read('test/keys/id_rsa')
  end

  describe 'when using hmac-sha256' do
    describe 'with defaults' do
      it 'creates a valid signature' do
        url = 'https://bolmaster2.com/foo'

        headers = {
          date: 'Fri, 10 Nov 2017 12:19:48 GMT'
        }

        output = HTTPSignature.create(
          url: url,
          headers: headers,
          key_id: 'test-key',
          key: 'boom'
        )

        expected = 'keyId="test-key",algorithm="hmac-sha256",headers="(request-target) host date",signature="MDAyMDYxNWRhMmEwNDhiMTQ1MDc0MTFjNWZlNjYwYjY2MTkzNDUzMDE5OGU3ZDRhY2E4MzNiNWNmNTlmYzViYw=="'

        assert_equal expected, output
      end
    end

    describe 'when using hmac-sha512' do
      describe 'with defaults' do
        it 'creates a valid signature' do
          url = 'https://bolmaster2.com/foo'
  
          headers = {
            date: 'Fri, 10 Nov 2017 12:19:48 GMT'
          }
  
          output = HTTPSignature.create(
            url: url,
            headers: headers,
            key_id: 'test-key',
            key: 'boom',
            algorithm: 'hmac-sha512'
          )
  
          expected = 'keyId="test-key",algorithm="hmac-sha512",headers="(request-target) host date",signature="OTQ1MWY4NmNhMDMwM2Q1ZWJlZjA4ZjFmZTE5ODdhZTQ4NjhlOTM4MmQ2MGU2Y2Y5NjkyMjQ1MThkZmY4MDE2NDhiNjdmOTgwNzg0MGQ4NGQ4OWFhODhmNTdjZmM0YzgyYjcwNmRjNmFlYWE2NDgzNDc3Nzk0NjY1NGEzYTQyZmE="'
  
          assert_equal expected, output
        end
      end
    end

    describe 'when query string is used in both params and in url' do
      it 'appends the query_string_params' do
        url = 'https://bolmaster2.com/?ok=god'
        key = 'boom'

        params = {
          boom: 'omg',
          wtf: 'lol'
        }

        headers = {
          date: 'Fri, 10 Nov 2017 12:19:48 GMT'
        }

        output = HTTPSignature.create(
          url: url,
          query_string_params: params,
          headers: headers,
          key_id: 'test-key',
          key: key,
          algorithm: 'hmac-sha256'
        )

        string_to_sign = [
          "(request-target): get /?ok=god&boom=omg&wtf=lol",
          "host: bolmaster2.com",
          "date: Fri, 10 Nov 2017 12:19:48 GMT"
        ].join("\n")

        expected_signature = Base64.strict_encode64(
          HTTPSignature.sign(string_to_sign, key: key, algorithm: 'hmac-sha256')
        )

        expected = 'keyId="test-key",algorithm="hmac-sha256",headers="(request-target) host date",signature="'+expected_signature+'"'

        assert_equal expected, output
      end
    end

    describe 'with post data' do
      it 'includes digest as header' do
        skip
      end
    end
  end

  describe 'when using rsa-sha256' do
    # https://tools.ietf.org/html/draft-cavage-http-signatures-08#appendix-C.2
    describe 'with basic example from draft' do
      it 'creates a valid signature' do
        params = {
          param: 'value',
          pet: 'dog'
        }

        headers = {
          date: 'Thu, 05 Jan 2014 21:31:40 GMT'
        }

        output = HTTPSignature.create(
          url: 'https://example.com/foo',
          method: :post,
          query_string_params: params,
          headers: headers,
          key_id: 'Test',
          algorithm: 'rsa-sha256',
          key: OpenSSL::PKey::RSA.new(private_key)
        )

        expected_signature = 'HUxc9BS3P/kPhSmJo+0pQ4IsCo007vkv6bUm4Qehrx+B1Eo4Mq5/6KylET72ZpMUS80XvjlOPjKzxfeTQj4DiKbAzwJAb4HX3qX6obQTa00/qPDXlMepD2JtTw33yNnm/0xV7fQuvILN/ys+378Ysi082+4xBQFwvhNvSoVsGv4='

        expected = 'keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date",signature="'+expected_signature+'"'

        assert_equal expected, output
      end
    end

    # https://tools.ietf.org/html/draft-cavage-http-signatures-08#appendix-C.3
    describe 'with all headers and body' do
      it 'creates a valid signature' do
        params = {
          param: 'value',
          pet: 'dog'
        }

        headers = {
          date: 'Thu, 05 Jan 2014 21:31:40 GMT',
          'content-type': 'application/json',
          digest: HTTPSignature.create_digest('{"hello": "world"}'),
          'content-length': '18'
        }

        output = HTTPSignature.create(
          url: 'https://example.com/foo',
          method: :post,
          query_string_params: params,
          headers: headers,
          key_id: 'Test',
          algorithm: 'rsa-sha256',
          key: OpenSSL::PKey::RSA.new(private_key)
        )

        expected_signature = 'Ef7MlxLXoBovhil3AlyjtBwAL9g4TN3tibLj7uuNB3CROat/9KaeQ4hW2NiJ+pZ6HQEOx9vYZAyi+7cmIkmJszJCut5kQLAwuX+Ms/mUFvpKlSo9StS2bMXDBNjOh4Auj774GFj4gwjS+3NhFeoqyr/MuN6HsEnkvn6zdgfE2i0='
        expected = 'keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date content-type digest content-length",signature="'+expected_signature+'"'

        assert_equal expected, output
      end
    end
  end
end
