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
          Host: 'bolmaster2.com',
          Date: 'Fri, 10 Nov 2017 12:19:48 GMT',
        }

        output = HTTPSignature.create(
          url: url,
          headers: headers,
          key_id: 'test-key',
          key: 'boom'
        )

        expected_signature = 'ACBhXaKgSLFFB0EcX+ZgtmGTRTAZjn1KyoM7XPWfxbw='
        expected = 'keyId="test-key",algorithm="hmac-sha256",headers="(request-target) host date",signature="'+expected_signature+'"'

        assert_equal expected, output
      end
    end

    describe 'when using hmac-sha512' do
      describe 'with defaults' do
        it 'creates a valid signature' do
          url = 'https://bolmaster2.com/foo'

          headers = {
            Host: 'bolmaster2.com',
            date: 'Fri, 10 Nov 2017 12:19:48 GMT'
          }

          output = HTTPSignature.create(
            url: url,
            headers: headers,
            key_id: 'test-key',
            key: 'boom',
            algorithm: 'hmac-sha512'
          )
          expected_signature = 'lFH4bKAwPV6+8I8f4Zh65IaOk4LWDmz5aSJFGN/4AWSLZ/mAeEDYTYmqiPV8/EyCtwbcauqmSDR3eUZlSjpC+g=='
          expected = 'keyId="test-key",algorithm="hmac-sha512",headers="(request-target) host date",signature="'+expected_signature+'"'

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
          Host: 'bolmaster2.com',
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
          Host: 'example.com',
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

      it 'validates a signature with the public key' do
        params = {
          url: 'https://example.com/foo',
          method: :post,
          query_string_params: {
            param: 'value',
            pet: 'dog'
          },
          headers: {
            host: 'example.com',
            date: 'Thu, 05 Jan 2014 21:31:40 GMT'
          },
          key_id: 'Test',
          algorithm: 'rsa-sha256',
          key: OpenSSL::PKey::RSA.new(private_key)
        }

        output = HTTPSignature.create(**params)

        # Use the same params as when created the signature, but add signature
        # and change the private to the public key and remove the :key_id which
        # isn't used
        params[:headers][:signature] = output
        params[:key] = OpenSSL::PKey::RSA.new(public_key)
        params.delete(:key_id)

        valid = HTTPSignature.valid?(**params)

        assert valid, 'RSA-SHA256 signature is not valid'
      end
    end

    # https://tools.ietf.org/html/draft-cavage-http-signatures-08#appendix-C.3
    describe 'with all headers and body' do
      it 'creates a valid signature' do
        params = {
          param: 'value',
          pet: 'dog'
        }

        body = '{"hello": "world"}'

        headers = {
          host: 'example.com',
          date: 'Thu, 05 Jan 2014 21:31:40 GMT',
          'content-type': 'application/json',
          digest: HTTPSignature.create_digest(body),
          'content-length': '18'
        }

        output = HTTPSignature.create(
          url: 'https://example.com/foo',
          method: :post,
          query_string_params: params,
          headers: headers,
          key_id: 'Test',
          algorithm: 'rsa-sha256',
          key: OpenSSL::PKey::RSA.new(private_key),
          body: body
        )

        expected_signature = 'Ef7MlxLXoBovhil3AlyjtBwAL9g4TN3tibLj7uuNB3CROat/9KaeQ4hW2NiJ+pZ6HQEOx9vYZAyi+7cmIkmJszJCut5kQLAwuX+Ms/mUFvpKlSo9StS2bMXDBNjOh4Auj774GFj4gwjS+3NhFeoqyr/MuN6HsEnkvn6zdgfE2i0='
        expected = 'keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date content-type digest content-length",signature="'+expected_signature+'"'

        assert_equal expected, output
      end
    end
  end

  describe 'when using rsa-sha512' do
    describe 'with defaults' do
      it 'creates a valid signature' do
        url = 'https://bolmaster2.com/foo'

        headers = {
          host: 'bolmaster2.com',
          date: 'Fri, 10 Nov 2017 12:19:48 GMT'
        }

        output = HTTPSignature.create(
          url: url,
          headers: headers,
          key_id: 'test-key',
          key: OpenSSL::PKey::RSA.new(private_key),
          algorithm: 'rsa-sha512'
        )

        expected_signature = 'RfccrjiL2x43pc5wwM47EkHKO6/Vqn1bCFbbk70Tb4DggmChKZAl/lP+YmScOv550fqoctDHl0/4KXN59yko8knvPD8upAhxwegNiFqZB11n/0II+OkDAldKHlgMDfzW2+3Y2I169Nd/fGOV7iALOK8mA6wFSCFAWwbFp1PhAcI='
        expected = 'keyId="test-key",algorithm="rsa-sha512",headers="(request-target) host date",signature="'+expected_signature+'"'

        assert_equal expected, output
      end
    end
  end

  describe '.create_query_string' do
    describe 'when query string is used only in url' do
      it 'creates correct query string' do
        query_string = '?param1=value1&param2=value2'
        url = 'http://localhost/omg' + query_string
        uri = URI(url)

        output = HTTPSignature.create_query_string(uri, {})

        assert_equal query_string, output
      end
    end

    describe 'when query string is used only in query_string_params' do
      it 'creates correct query string' do
        uri = URI('http://localhost/omg')
        output = HTTPSignature.create_query_string(uri, param1: 'value1', param2: 'value2')
        expected = '?param1=value1&param2=value2'

        assert_equal expected, output
      end
    end
  end

  describe '.config' do
    describe 'with keys' do
      it 'makes the keys accessible' do
        keys = [{ id: 'key-1', value: 'asdf' }]
        HTTPSignature.config(keys: keys)

        assert_equal keys, HTTPSignature.keys
      end

      it 'can pick a key from id' do
        keys = [{ id: 'key-1', value: 'asdf' }]

        HTTPSignature.config(keys: keys)

        assert_equal 'asdf', HTTPSignature.key('key-1')
      end
    end
  end
end
