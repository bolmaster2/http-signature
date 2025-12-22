# HTTP Signature
[![CircleCI](https://circleci.com/gh/bolmaster2/http-signature.svg?style=svg)](https://circleci.com/gh/bolmaster2/http-signature)

Create and validate HTTP Message Signatures per [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) using the `Signature-Input` and `Signature` headers.

Aims to only implement the creation and validation of signatures without any external dependencies. Adapters are provided for common HTTP libraries.

__NOTE__: RFC 9421 signs components via two headers:
```
Signature-Input: sig1=("@method" "@authority" "@target-uri" "date");created=...
Signature: sig1=:BASE64_SIGNATURE_BYTES:
```

## Installation
```
gem install http_signature
```

## Usage

```ruby
require 'http_signature'
```

### Creating signature headers
`HTTPSignature.create` returns both `Signature-Input` and `Signature`. The default algorithm is `hmac-sha256`.
```ruby
headers = { 'date' => 'Tue, 20 Apr 2021 02:07:55 GMT' }

sig_headers = HTTPSignature.create(
  url: 'https://example.com/foo?pet=dog',
  method: :get,
  headers: headers,
  key_id: 'Test',
  key: 'secret 🙈',
  covered_components: %w[@method @authority @target-uri date],
  created: 1_618_884_473
)

request['Signature-Input'] = sig_headers['Signature-Input']
request['Signature'] = sig_headers['Signature']
```

### With headers, query parameters and a body
When `content-digest` is covered, it is computed automatically from the body.

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

sig_headers = HTTPSignature.create(
  url: 'https://example.com/foo',
  method: :post,
  query_string_params: params,
  headers: headers,
  key_id: 'rsa-1',
  algorithm: 'rsa-pss-sha256',
  key: File.read('key.pem'), # private key
  body: body,
  covered_components: %w[@method @authority @target-uri date content-digest]
)

request['Signature-Input'] = sig_headers['Signature-Input']
request['Signature'] = sig_headers['Signature']
```

### Validate asymmetric signature
Pass the incoming `Signature-Input` and `Signature` headers and the public key.
```ruby
HTTPSignature.valid?(
  url: request.url, # full URL including authority
  method: request.method,
  headers: request.headers,
  body: request.body,
  key: OpenSSL::PKey::RSA.new('public_key.pem'), # public key
  signature_input_header: request.get_header('Signature-Input'),
  signature_header: request.get_header('Signature')
)
```

## Example usage on the request flow
### NET::HTTP
Example of using it with `NET::HTTP`. There's no real integration written so it's basically just
getting the request object's data and create the signature and adding it to the headers.

```ruby
require 'net/http'
require 'http_signature'

uri = URI('http://example.com/hello')

Net::HTTP.start(uri.host, uri.port) do |http|
  request = Net::HTTP::Get.new(uri)

  sig_headers = HTTPSignature.create(
    url: request.uri,
    method: request.method,
    headers: request.each_header.map { |k, v| [k, v] }.to_h,
    key: 'MYSECRETKEY',
    key_id: 'KEY_1',
    algorithm: 'hmac-sha256',
    body: request.body ? request.body : ''
  )

  request['Signature-Input'] = sig_headers['Signature-Input']
  request['Signature'] = sig_headers['Signature']

  response = http.request(request) # Net::HTTPResponse
end
```

### Faraday middleware
Outgoing requests automatically receive `Signature-Input` and `Signature`.

```ruby
require 'http_signature/faraday'

HTTPSignature::Faraday.key = 'MySecureKey' # This should be long and random
HTTPSignature::Faraday.key_id = 'key-1' # For the recipient to know which key to decrypt with

# Tell faraday to use the middleware. Read more about it here: https://github.com/lostisland/faraday#advanced-middleware-usage
Faraday.new('http://example.com') do |faraday|
  faraday.use(HTTPSignature::Faraday)
  faraday.adapter(Faraday.default_adapter)
end

# Now this request will contain the `Signature-Input` and `Signature` headers
response = conn.get('/')

# Request looking like:
# Signature-Input: sig1=("@method" "@authority" "@target-uri" "date");created=...
# Signature: sig1=:BASE64_SIGNATURE:
```

### Rack middleware for incoming requests
Rack middlewares sits in between your app and the HTTP request and validate the signature before hitting your app. Read more about [rack middlewares here](https://codenoble.com/blog/understanding-rack-middleware/).
```
Client <-> Middleware -> App
```

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

## Why/when should I use this?
In short: When you need to make sure that the request or response has not been tampered with (_integrity_). And you can be sure that the request was sent by someone that had the key (_authenticity_). Don't confuse this with encryption, the signed message is not encrypted. It's just _signed_. You could add a layer of encryption on top of this. Or just use HTTPS and you're _kinda safe_ for not that much hassle, which is totally fine in most cases.

[Read more about HMAC here](https://security.stackexchange.com/questions/20129/how-and-when-do-i-use-hmac/20301), even though you can sign your messages with RSA as well, but it's the same principle.
