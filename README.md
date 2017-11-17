# HTTP Signature
Create and validate HTTP request signature according to this draft: https://tools.ietf.org/html/draft-cavage-http-signatures-08

Aims to only implement the creation of the signature without any external dependencies.

## Usage

### Basic
The most basic usage without any extra headers. If no `date` header is provided it will be automatically created (TODO: make it required). The default algorithm is `hmac-sha256`.
```ruby
HTTPSignature.create(
  url: 'https://example.com/foo',
  key_id: 'Test',
  key: 'secret 🙈'
)
# This will yield the value to use in the `Signature` header:
# 'keyId="test-key",algorithm="hmac-sha256",headers="(request-target) host date",signature="MDAyMDYxNWRhMmEwNDhiMTQ1MDc0MTFjNWZlNjYwYjY2MTkzNDUzMDE5OGU3ZDRhY2E4MzNiNWNmNTlmYzViYw=="'
```

### With headers and query string parameters
Also shows how to set `rsa-sha256` as algorithm.
```ruby
params = {
  param: 'value',
  pet: 'dog'
}

body = '{"hello": "world"}'

headers = {
  date: 'Thu, 05 Jan 2014 21:31:40 GMT',
  'content-type': 'application/json',
  digest: HTTPSignature.create_digest(body),
  'content-length': body.length
}

HTTPSignature.create(
  url: 'https://example.com/foo',
  method: :post,
  params: params,
  headers: headers,
  key_id: 'Test',
  algorithm: 'rsa-sha256',
  key: OpenSSL::PKey::RSA.new(File.read('key.pem')),
  body: body
)
# 'keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date content-type digest content-length",signature="Ef7MlxLXoBovhil3AlyjtBwAL9g4TN3tibLj7uuNB3CROat/9KaeQ4hW2NiJ+pZ6HQEOx9vYZAyi+7cmIkmJszJCut5kQLAwuX+Ms/mUFvpKlSo9StS2bMXDBNjOh4Auj774GFj4gwjS+3NhFeoqyr/MuN6HsEnkvn6zdgfE2i0="'
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
# 'keyId="Test",algorithm="hmac-sha256",headers="(request-target) host date digest",signature="NjQ2NzkxMGEwZDYwYmYxNjBlZGQyMmJlZDlkZTgxMDkyN2FhNzBkMzBjYjYyMDRiYTU3YzRiZjkzZGI1NWY3OA=="'
```
## Test
```
rake test
```
