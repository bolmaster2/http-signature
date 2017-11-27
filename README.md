# HTTP Signature
Create and validate HTTP request signature according to this draft: https://tools.ietf.org/html/draft-cavage-http-signatures-08

Aims to only implement the creation of the signature without any external dependencies.
The idea is to implement adapters to popular http libraries to make it easy to use.

## Usage

### Basic
The most basic usage without any extra headers. If no `date` header is provided it will be automatically created (_TODO: make it required_). The default algorithm is `hmac-sha256`.
```ruby
HTTPSignature.create(
  url: 'https://example.com/foo',
  key_id: 'Test',
  key: 'secret 🙈'
)
# 'keyId="test-key",algorithm="hmac-sha256",headers="(request-target) host date",signature="MDAyMDYxNWRhMmEwNDhiMTQ1MDc0MTFjNWZlNjYwYjY2MTkzNDUzMDE5OGU3ZDRhY2E4MzNiNWNmNTlmYzViYw=="'
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
- Implement all algorithms:
  - rsa-sha1
  - rsa-sha512
  - dsa-sha1
  - hmac-sha1
  - hmac-sha512
- When creating the signing string, follow the spec exactly:
  https://tools.ietf.org/html/draft-cavage-http-signatures-08#section-2.3,
  e.g, concatenate multiple instances of the same headers and remove surrounding whitespaces
- Make `date` header required, it's useless to auto create it as it's impossible
  for someone to know the exact value of it afterwards and thus impossible to recreate
  and then validate the signature.
- Implement adapters for http libraries
