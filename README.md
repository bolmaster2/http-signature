# HTTP Signature
[![CircleCI](https://circleci.com/gh/blmstr/http-signature/tree/master.svg?style=svg)](https://circleci.com/gh/blmstr/http-signature/tree/master)

Create and validate HTTP request signature according to this draft: https://tools.ietf.org/html/draft-cavage-http-signatures-08

Aims to only implement the creation of the signature without any external dependencies.
The idea is to implement adapters to popular http libraries to make it easy to use.

## Usage

### Basic
The most basic usage without any extra headers. The default algorithm is `hmac-sha256`.
```ruby
HTTPSignature.create(
  url: 'https://example.com/foo',
  key_id: 'Test',
  key: 'secret 🙈'
)
# 'keyId="Test",algorithm="hmac-sha256",headers="(request-target)",signature="OQ/dHqRW9vFmrW/RCHg7O2Fqx+3uqxJw81p6k9Rcyo4="'
```

### With headers, query parameters and a body
Uses both query parameters (in query string) and a `json` body as a `POST` request.
Also shows how to set `rsa-sha256` as algorithm. The `digest` is as you see basically
a `sha-256` digest of the request body.

```ruby
params = {
  param: 'value',
  pet: 'dog'
}

body = '{"hello": "world"}'

headers = {
  'date': 'Thu, 05 Jan 2014 21:31:40 GMT',
  'content-type': 'application/json',
  'digest': HTTPSignature.create_digest(body),
  'content-length': body.length
}

HTTPSignature.create(
  url: 'https://example.com/foo',
  method: :post,
  query_string_params: params,
  headers: headers,
  key_id: 'Test',
  algorithm: 'rsa-sha256',
  key: File.read('key.pem'),
  body: body
)
```

### With digest header auto-added
When digest header is omitted it's auto added as last header generated from the `body`:

```ruby
body = '{"foo": "bar"}'

HTTPSignature.create(
  url: 'https://example.com/foo',
  key_id: 'Test',
  key: 'secret 🙈',
  body: body
)
# 'keyId="Test",algorithm="hmac-sha256",headers="(request-target) digest",signature="3Jm5jnCSKX3fYLd58RqRdafZKeuSbUEPhn7grCGx4vg="'
```

### Validate asymmetric signature
With an asymmetric algorithm you can't just recreate the same header and see if they
check out, because you need the private key to do that and because the one validating
the signature should only have access to the public key, you need to validate it with that.

```ruby
params = {
  url: 'https://example.com/foo',
  method: :post,
  query_string_params: {
    param: 'value',
    pet: 'dog'
  },
  headers: {
    date: 'Thu, 05 Jan 2014 21:31:40 GMT'
  },
  key_id: 'Test',
  algorithm: 'rsa-sha256',
  key: OpenSSL::PKey::RSA.new('private_key.pem')
}

# First we create the signature with the private key and all the request data
signature_header = HTTPSignature.create(**params)
# 'keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date content-type digest content-length",signature="Ef7MlxLXoBovhil3AlyjtBwAL9g4TN3tibLj7uuNB3CROat/9KaeQ4hW2NiJ+pZ6HQEOx9vYZAyi+7cmIkmJszJCut5kQLAwuX+Ms/mUFvpKlSo9StS2bMXDBNjOh4Auj774GFj4gwjS+3NhFeoqyr/MuN6HsEnkvn6zdgfE2i0="'

# Then modify the params hash a bit to fit the `valid?` method
params[:signature] = output
params[:key] = OpenSSL::PKey::RSA.new('public_key.pem')
params.delete(:key_id)

HTTPSignature.valid?(**params) # true
```

## Setup
```
bundle install
```

## Test
The tests are written with `minitest` using specs. Run them all with `rake`:
```bash
rake test
```
Or a single with pattern matching:
```bash
rake test TEST=test/http_signature_test.rb TESTOPTS="--name=/appends\ the\ query_string_params/"
```

## License
This project is licensed under the terms of the [MIT license](https://opensource.org/licenses/MIT).

## Todo
- Implement algorithms:
  - ecdsa-sha256
- When creating the signing string, follow the spec exactly:
  https://tools.ietf.org/html/draft-cavage-http-signatures-08#section-2.3,
  e.g, concatenate multiple instances of the same headers and remove surrounding whitespaces
- Implement adapters for http libraries
