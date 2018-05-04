# HTTP Signature
[![CircleCI](https://circleci.com/gh/bolmaster2/http-signature.svg?style=svg)](https://circleci.com/gh/bolmaster2/http-signature)

Create and validate HTTP request signature according to this draft: https://tools.ietf.org/html/draft-cavage-http-signatures-08

Aims to only implement the creation and validation of the signature without any external dependencies.
The idea is to implement adapters to popular http libraries to make it easy to use.

__NOTE__: Only implements the `Signature` header and not the `Authorization` header, for now.

## Installation
```
gem install http_signature
```

## Usage

```ruby
require 'http_signature'
```

### Basic
The most basic usage without any extra headers. The default algorithm is `hmac-sha256`. This create the `Signature` header value. Next step is to add the value to the header and 💥 you're done! Note that this isn't very usable in the real world as it's very easy to do a replay attack. Because there's no value
that change. This is easy solved by adding the `Date` header which is recommended to add to every
request.
```ruby
HTTPSignature.create(
  url: 'https://example.com/foo',
  key_id: 'Test',
  key: 'secret 🙈'
)
# 'keyId="Test",algorithm="hmac-sha256",headers="(request-target)",signature="OQ/dHqRW9vFmrW/RCHg7O2Fqx+3uqxJw81p6k9Rcyo4="'
```

### With headers, query parameters and a body
Uses both query string parameters and a `json` body as a `POST` request.
Also shows how to set `rsa-sha256` as algorithm which signs with a private key.

```ruby
params = {
  param: 'value',
  pet: 'dog'
}

body = '{"hello": "world"}'

headers = {
  'date': 'Thu, 05 Jan 2014 21:31:40 GMT',
  'content-type': 'application/json',
  'content-length': body.length
}

HTTPSignature.create(
  url: 'https://example.com/foo',
  method: :post,
  query_string_params: params,
  headers: headers,
  key_id: 'rsa-1',
  algorithm: 'rsa-sha256',
  key: File.read('key.pem'), # private key
  body: body
)
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

## Example usage
### NET::HTTP
Example of using it with `NET::HTTP`. There's no real integration written so it's basically just
getting the request object's data and create the signature and adding it to the headers.

```ruby
require 'net/http'
require 'http_signature'

uri = URI('http://example.com/hello')

Net::HTTP.start(uri.host, uri.port) do |http|
  request = Net::HTTP::Get.new(uri)

  signature = HTTPSignature.create(
    url: request.uri,
    method: request.method,
    headers: request.each_header.map { |k, v| [k, v] }.to_h,
    key: 'MYSECRETKEY',
    key_id: 'KEY_1',
    algorithm: 'hmac-sha256',
    body: request.body ? request.body : ''
  )

  request['Signature'] = signature

  response = http.request(request) # Net::HTTPResponse
end
```

### Faraday middleware
Example of using it with an outgoing faraday request. IMO, this is the smoothest usage.
Basically you set the keys and tell faraday to use the middleware.

```ruby
require 'http_signature/faraday'

HTTPSignature::Faraday.key = 'MySecureKey' # This should be long and random
HTTPSignature::Faraday.key_id = 'key-1' # For the recipient to know which key to decrypt with

# Tell faraday to use the middleware. Read more about it here: https://github.com/lostisland/faraday#advanced-middleware-usage
Faraday.new('http://example.com') do |faraday|
  faraday.use(HTTPSignature::Faraday)
  faraday.adapter(Faraday.default_adapter)
end

# Now this request will contain the `Signature` header
response = conn.get('/')

# Request looking like:
# GET / HTTP/1.1
# User-Agent: Faraday v0.15.0
# Signature: keyId="key-1",algorithm="hmac-sha256",headers="(request-target) date",signature="EzFa4vb0z+VFF8VYt9qQlzF9MTf5Izptc02OJ7aajnU="
```

### Rack middleware for incoming requests
I've written a quite sloppy but totally usable rack middleware that validates incoming requests.

#### General Rack application
Sinatra for example
```ruby
require 'http_signature/rack'

HTTPSignature.config(keys: [{ id: 'key-1', value: 'MySecureKey' }])
# You can exclude paths where you don't want to validate the signature, it's using
# regexp so you can use `*` and stuff like that. Just watch out so you don't exclude
# more paths than intended. Regexp can trick you when you least expect it 👻.
HTTPSignature::Rack.exclude_paths = ['/', '/hello/*']

use HTTPSignature::Rack
run MyApp
```

#### Rails
Checkout [this documentation](http://guides.rubyonrails.org/rails_on_rack.html). But in short, add this inside the config block:
```ruby
require 'http_signature/rack' # This doesn't have to be inside the block
config.middleware.use HTTPSignature::Rack
```

Don't forget to set the keys somewhere, an initializer should be suitable. Multiple keys
are supported to be able to easily be rotated.
```ruby
HTTPSignature.config(keys: [{ id: 'key-1', value: 'MySecureKey' }])
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
