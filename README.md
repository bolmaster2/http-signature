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

```shell
gem install http_signature
```

## Usage

```ruby
require 'http_signature'
```

### Create signature

`HTTPSignature.create` returns both `Signature-Input` and `Signature`. The default algorithm is `hmac-sha256`.
```ruby
headers = { 'date' => 'Tue, 20 Apr 2021 02:07:55 GMT' }

sig_headers = HTTPSignature.create(
  url: 'https://example.com/foo?pet=dog',
  method: :get,
  headers: headers,
  key_id: 'Test',
  key: 'secret',
  covered_components: %w[@method @authority @target-uri date],
  created: 1_618_884_473
)

request['Signature-Input'] = sig_headers['Signature-Input']
request['Signature'] = sig_headers['Signature']
```

#### With headers, query parameters and a body
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

### Validate signature

Call `valid?` with the incoming request headers (including `Signature-Input` and `Signature`) and the key.

```ruby
HTTPSignature.valid?(
  url: "https://example.com/foo",
  method: :get,
  headers: headers,
  key: "secret"
)
```

## Outgoing examples

### NET::HTTP

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

### Faraday

As a faraday middleware

```ruby
require 'http_signature/faraday'

# Specify key
HTTPSignature::Faraday.key = 'secret'
HTTPSignature::Faraday.key_id = 'key-1'

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

## Incoming request examples

### Rack middleware
Rack middlewares sits in between your app and the HTTP request and validate the signature before hitting your app. Read more about [rack middlewares here](https://codenoble.com/blog/understanding-rack-middleware/).

Here is how it could be used with sinatra:

```ruby
require 'http_signature/rack'

HTTPSignature.config(keys: [{ id: 'key-1', value: 'MySecureKey' }])
HTTPSignature::Rack.exclude_paths = ['/', '/hello/*']

use HTTPSignature::Rack
run MyApp
```

### Rails
Opt-in per controller/action using a before_action.
```ruby
# app/controllers/api/base_controller.rb

require 'http_signature/rails'

class Api::BaseController < ApplicationController
  include HTTPSignature::Rails::Controller

  before_action :verify_http_signature!
end
```

Set the keys in an initializer
```ruby
# config/initializers/http_signature.rb

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
