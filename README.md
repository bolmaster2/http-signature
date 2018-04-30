# HTTP Signature
[![CircleCI](https://circleci.com/gh/bolmaster2/http-signature.svg?style=svg)](https://circleci.com/gh/bolmaster2/http-signature)

Create and validate HTTP request signature according to this draft: https://tools.ietf.org/html/draft-cavage-http-signatures-08

Aims to only implement the creation and validation of the signature without any external dependencies.
The idea is to implement adapters to popular http libraries to make it easy to use.

## Installation
```
gem install http_signature
```

## Usage

```ruby
require 'http_signature'
```

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

Imagine the incoming HTTP request looks like this:
```
POST /foo HTTP/1.1
Host: example.com
Date: Thu, 05 Jan 2014 21:31:40 GMT
Content-Type: application/json
Content-Length: 18
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Signature: keyId="Test-1",algorithm="rsa-sha256",headers="(request-target) host date content-type content-length digest",signature="YGPVM1tGHD7CHgTmroy9apLtVazdESzMl4vj1koYHNCMmTEDor4Om5TDZDFaJdny5dF3gq+PQQuPwyknNEvACmSjwVXzljPFxaY/JMZTqAdD0yHTP2Rx0Y/J4GwgKARWTZUmccfVYsXp86PhIlCymzleZzYCzj6shyg9NB7Ht+k="

{"hello": "world"}
```

Let's assume we have this request ☝️ in a `request` object for the sake of the example:
```ruby
HTTPSignature.valid?(
  url: request.url,
  method: request.method,
  headers: request.headers,
  body: request.body,
  key: OpenSSL::PKey::RSA.new('public_key.pem'),
  algorithm: 'rsa-sha256'
)
```

## Example usage with middleware
### Faraday middleware on outgoing requests
Example of using it on an outgoing request.
```ruby
require 'http_signature/faraday'
# Two variables needed to be set
HTTPSignature::Faraday.key = 'MySecureKey' # This should be long and random
HTTPSignature::Faraday.key_id = 'key-1' # For the recipient to know which key to decrypt with


# Tell faraday to use the middleware. Read more about it here: https://github.com/lostisland/faraday#advanced-middleware-usage
Faraday.new('http://example.com') do |faraday|
  faraday.use(HTTPSignature::Faraday)
  faraday.adapter(Faraday.default_adapter)
end

# Now this request will contain the `Signature` header
response = conn.get('/')
```

### Rack middleware for incoming requests
I've written a quite sloppy but totally usable rack middleware that validates every incoming request.

#### General rack application
Sinatra for example
```ruby
require 'http_signature/rack'

HTTPSignature.config(keys: [{ id: 'key-1', value: 'MySecureKey' }])

use HTTPSignature::Rack
run MyApp
```

#### Rails
Checkout [this documentation](http://guides.rubyonrails.org/rails_on_rack.html). But in short, add this inside the config block:
```ruby
require 'http_signature/rack' # This doesn't have to be inside the block
config.middleware.use HTTPSignature::Rack
```

and don't forget to set the key env somewhere, an initializer should be suitable:
```ruby
HTTPSignature.config(keys: [{ id: 'key-1', value: 'MySecureKey' }])

# You can exclude paths where the middleware just pass the request along without caring about anything...
HTTPSignature::Rack.exclude_paths = ['/']
```


## Development
Install dependencies and then you can start running the tests!
```
bundle install
```

### Test
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
- Add more example of use with different http libraries
- Refactor `.valid?` to support all algorithms
- Implement algorithms:
  - ecdsa-sha256
- When creating the signing string, follow the spec exactly:
  https://tools.ietf.org/html/draft-cavage-http-signatures-08#section-2.3,
  e.g, concatenate multiple instances of the same headers and remove surrounding whitespaces
