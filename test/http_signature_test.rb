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

        expected = 'keyId="test-key",algorithm="hmac-sha256",headers="(request-target) host date",signature="gQI2QiFY/8BycVdSnkdCw6ww6HiJPQqnOPybmpSP9vU="'

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

          expected = 'keyId="test-key",algorithm="hmac-sha512",headers="(request-target) host date",signature="zo91KBsZnvCWMI4oJC6tHufJHvw/MMuBrUuxkly1MgUEFhE0R30DET+eYLiEYRRwt4P+Pcc9rSAsGOX+Q8fuNQ=="'

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
          "(request-target): GET /?ok=god&boom=omg&wtf=lol",
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

        expected_signature = 'ATKY9c9VlKL4HfGc9D64qEVqnA90U9UGV8qxHDF9RWs20NPdgDMJyDQc8FJKSA/4/psTuaIDJM3MG2YOTzqTkVd3VY+580DXVVjJ0dW9wwwr8BMCmitJpCiAf0IOm+cGwcs29YdB7Xb+tjy38Qn6e8MG8wldZayH3AxEqz2FBPI='
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

        expected_signature = 'P6yNZ1dOBMmuLEyPkhzINNP5GTy3kvM/b/epD9FcdHsihWevJBlR2om3Wd/X+bTHs9AztxZqjFkdQFyhs3Yo/rNie4rU8Ga/LAvInJTlpNGSmahkW6UMQTUsWRA8bFbfEMoTDgxMcXmu7tjcpdSDkOyow6nSjrekWw150Uss6nA='
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

        expected = 'keyId="test-key",algorithm="rsa-sha512",headers="(request-target) host date",signature="s0FPAbu2f49fjxa7Ia5rnjUPq/sRfTs+Xfl13Wqs92kDVIVOj7zY2qwbqQKe1pLfaimGwTT05HLiDFdbOFXiuylNTq7xI2l0JndNgIEdkJEITbQYPtIuakCfQosG1eQlsyYp2m2mLmrNURjoqyv9HkdKO6onchXc3lsou/Ne5rs="'

        assert_equal expected, output
      end
    end
  end
end
