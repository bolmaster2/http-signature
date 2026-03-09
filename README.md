# HTTP Signature

A Ruby gem for signing and verifying HTTP requests. You pick which parts of the request to sign (method, URL, headers, body), and the receiver can verify nothing was tampered with — and that it came from someone who holds the key.

Built on [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) (HTTP Message Signatures). Works with HMAC, RSA, ECDSA, and Ed25519.

When using a standard to sign your HTTP requests you don't need to write a custom implementation every time. There's [loads of libraries](https://httpsig.org/) across languages that's implementing it!

Use your favorite http clients to sign requests and your favorite frameworks to verify them, see [Outgoing request examples](#outgoing-request-examples) and [Incoming request examples](#incoming-request-examples)

## Installation

```shell
bundle add http_signature
```

## Usage

### Create signature

`HTTPSignature.create` returns `Signature-Input`, `Signature` and `Content-Digest` headers that you can include in your request.

This example will sign:
- The whole `url` string: `https://example.com/foo?pet=dog`
- The HTTP method: `POST`
- The headers `Content-Type` and `Content-Digest`
- The body, which is in the `Content-Digest` header and is automatically generated when a body is provided

```ruby
HTTPSignature.create(
  url: "https://example.com/foo?pet=dog",
  method: :post,
  key_id: "key-1",
  key: "secret",
  headers: {"Content-Type" => "application/json"},
  body: {payload: {foo: "bar"}}.to_json,
  components: %w[@method @target-uri content-type content-digest]
)
# =>
# {"Signature-Input" =>
#   "sig1=(\"@method\" \"@target-uri\" \"content-type\" \"content-digest\");created=1772541832;keyid=\"key-1\";alg=\"hmac-sha256\"",
#  "Signature" => "sig1=:5ij6rnnwS9oOtu78zU4yBFy9uL3ItXM7ug368cJZuTU=:",
#  "Content-Digest" => "sha-256=:zWToMIpmVcAx10/ZGOrMzi7HQyUBat/TskigQnncEQ8=:"}
```
#### All options

```ruby
HTTPSignature.create(
  url: "https://example.com/foo?pet=dog",
  method: :get,
  key_id: "Test",
  key: "secret",
  # Optional arguments
  headers: headers, # Default: {}
  body: "Hello world", # Default: ""
  components: %w[@method @target-uri date], # Default: %w[@method @target-uri content-digest content-type]
  created: Time.now.to_i, # Default: Time.now.to_i
  expires: Time.now.to_i + 600, # Default: nil
  nonce: "1", # Default: nil
  tag: "web-bot-auth", # Default: nil
  label: "sig1", # Default: "sig1"
  query_string_params: {pet2: "cat"}, # Default: {}, you can pass query string params both here and in the `url` param
  algorithm: "hmac-sha512", # Default: "hmac-sha256"
  include_alg: true, # Default: true, set to false to omit the alg parameter from Signature-Input
  status: 200, # Default: nil, required when signing responses with @status component
  attached_request: { headers: req_headers } # Default: nil, required when using ;req component parameter
)
```

#### Supported algorithms

| Algorithm | Key type |
|-----------|----------|
| `hmac-sha256` (default) | Shared secret string |
| `hmac-sha512` | Shared secret string |
| `rsa-pss-sha256` | RSA key (`OpenSSL::PKey::RSA`) |
| `rsa-pss-sha512` | RSA key |
| `rsa-v1_5-sha256` | RSA key |
| `ecdsa-p256-sha256` | EC key (P-256 curve) |
| `ecdsa-p384-sha384` | EC key (P-384 curve) |
| `ed25519` | Ed25519 key |

#### Supported components

Derived components (prefixed with `@`) per [RFC 9421 Section 2.2](https://www.rfc-editor.org/rfc/rfc9421#section-2.2):

| Component | Description |
|-----------|-------------|
| `@method` | HTTP method (e.g., `GET`, `POST`) |
| `@target-uri` | Full request URI (`https://example.com/foo?bar=1`) |
| `@authority` | Host (and port if non-default) |
| `@scheme` | URI scheme (`http` or `https`) |
| `@path` | Request path (`/foo`) |
| `@query` | Query string (including `?`; `?bar=1`) |
| `@query-param` | Individual query parameter (requires `;name`, e.g., `@query-param;name="pet"`) |
| `@request-target` | Request target (path + query) |
| `@status` | Response status code (responses only) |

Any lowercase header name (e.g., `content-type`, `date`) can also be used as a component.

Default components are: `@method @target-uri content-digest content-type`

#### Component parameters

Components can have parameters per [RFC 9421 Section 2.1](https://www.rfc-editor.org/rfc/rfc9421#section-2.1):

| Parameter | Description |
|-----------|-------------|
| `;sf` | Serialize the value as a structured field ([RFC 8941](https://www.rfc-editor.org/rfc/rfc8941)) |
| `;key="member"` | Extract a single dictionary member from a structured field |
| `;bs` | Use byte sequence serialization for the value |
| `;req` | Resolve the component from the attached request (see below) |
| `;name="param"` | Select a named query parameter (only with `@query-param`) |

Example using `;key` to sign only the `sha-256` member of `content-digest`:

```ruby
components: ["@method", "@target-uri", 'content-digest;key="sha-256"']
```

#### Signing responses bound to a request

When signing an HTTP response, you can bind it to the original request using the `;req` component parameter ([RFC 9421 Section 2.4](https://www.rfc-editor.org/rfc/rfc9421#section-2.4)). This cryptographically ties the response signature to values from the request, proving the response was generated for that specific request.

Pass the original request headers via `attached_request`:

```ruby
sig_headers = HTTPSignature.create(
  url: "https://example.com/api/data",
  method: "POST",
  headers: response_headers,
  components: ["@status", "content-type", "content-type;req", "@method;req"],
  status: 200,
  key: "secret",
  key_id: "key-1",
  attached_request: { headers: { "content-type" => "application/json" } }
)
```

Components with `;req` are resolved from the attached request's headers instead of the response headers. For verification, pass the same `attached_request`:

```ruby
HTTPSignature.valid?(
  url: "https://example.com/api/data",
  method: "POST",
  headers: response_headers,
  key: "secret",
  status: 200,
  attached_request: { headers: original_request_headers }
)
```

### Validate signature

Call `valid?` with the incoming request headers (including `Signature-Input` and `Signature`)

```ruby
HTTPSignature.valid?(
  url: "https://example.com/foo",
  method: :get,
  headers: headers,
  key: "secret"
)

# Returns true when all is good.
# Raises `SignatureError` for invalid signatures
```

#### All verification options

```ruby
HTTPSignature.valid?(
  url: "https://example.com/foo",
  method: :get,
  headers: headers,
  body: request_body, # Default: ""
  key: "secret", # Default: nil, uses key_resolver or configured keys if nil
  key_resolver: ->(key_id) { find_key(key_id) }, # Default: nil, called with the key_id from Signature-Input
  label: "sig1", # Default: nil (uses first)
  query_string_params: {}, # Default: {}
  max_age: 300, # Default: nil, reject signatures older than N seconds
  algorithm: "hmac-sha256", # Default: nil, uses alg from Signature-Input or hmac-sha256
  status: 200, # Default: nil, required when verifying responses with @status
  require_content_digest: true, # Default: false, raise if body present but content-digest not signed
  attached_request: { headers: req_headers } # Default: nil, required when ;req components were signed
)
```

#### Dynamic key resolution

Use `key_resolver` when you need to look up keys dynamically based on the `key_id` from the incoming signature:

```ruby
HTTPSignature.valid?(
  url: "https://example.com/foo",
  method: :get,
  headers: headers,
  key_resolver: ->(key_id) { KeyStore.find(key_id) }
)
```

Alternatively, configure keys globally:

```ruby
HTTPSignature.configure do |config|
  config.keys = [
    {id: "key-1", value: "secret1"},
    {id: "key-2", value: "secret2"}
  ]
end
```

#### Limiting signature age

Use `max_age` to reject signatures older than a specified number of seconds, regardless of the signature's `expires` parameter. This helps protect against replay attacks.

```ruby
HTTPSignature.valid?(
  url: "https://example.com/foo",
  method: :get,
  headers: headers,
  key: "secret",
  max_age: 300 # Reject signatures older than 5 minutes
)

# Raises `ExpiredError` if the signature was created more than 300 seconds ago
```

### Content-Digest

When `content-digest` is included in the signed components and a body is present, the gem handles [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530) Content-Digest automatically:

- **Signing** (`create`): If the request has a body and no `Content-Digest` header, the gem generates one using SHA-256 and adds it to the headers. If the header already exists, it verifies it matches the body.
- **Verification** (`valid?`): Verifies that the `Content-Digest` header matches the body. Raises `MissingComponent` if the header is absent, and `SignatureError` on mismatch.

To enforce that every request with a body must have `content-digest` in its signed components, use `require_content_digest: true` during verification.

### Error handling

All errors inherit from `HTTPSignature::SignatureError`:

| Error | Raised when |
|-------|-------------|
| `SignatureError` | Signature is invalid, headers are missing, or Content-Digest mismatches |
| `MissingComponent` | A signed component is not present in the request |
| `UnsupportedComponent` | An unknown derived component is used (e.g., `@foo`) |
| `UnsupportedAlgorithm` | The signing algorithm is not supported |
| `ExpiredError` | The signature has expired (via `expires` or `max_age`) |

```ruby
begin
  HTTPSignature.valid?(url:, method:, headers:, key:)
rescue HTTPSignature::ExpiredError
  # Signature too old
rescue HTTPSignature::SignatureError => e
  # Any other signature problem
end
```

## Outgoing request examples

### Net::HTTP

```ruby
require "net/http"
require "http_signature"

uri = URI("http://example.com/hello")
body = {name: "World"}.to_json
headers = {"Content-Type" => "application/json"}

sig_headers = HTTPSignature.create(
  url: uri.to_s,
  method: :post,
  headers:,
  key: "MYSECRETKEY",
  key_id: "KEY_1",
  body:
)

req = Net::HTTP::Post.new(uri)
headers.merge(sig_headers).each { |k, v| req[k] = v }
req.body = body

Net::HTTP.start(uri.host, uri.port) { |http| http.request(req) }
```

### Faraday

As a Faraday middleware

```ruby
require "http_signature/faraday"

HTTPSignature::Faraday.key = "secret"
HTTPSignature::Faraday.key_id = "key-1"

conn = Faraday.new("http://example.com") do |f|
  f.use(HTTPSignature::Faraday)
end

# Requests will automatically include Signature-Input, Signature, and Content-Digest headers
conn.post("/hello") do |req|
  req.headers["Content-Type"] = "application/json"
  req.body = {name: "World"}.to_json
end
```

Example with setting params per request:

```ruby
conn = Faraday.new("http://example.com") do |f|
  f.use(
    HTTPSignature::Faraday,
    key: "secret",
    key_id: "key-1",
    components: ["@method", "@target-uri", "content-type", "content-digest"]
  )
end
```

The middleware also accepts the params: `created:`, `expires:`, `nonce:`, `tag:`, `label:`, `algorithm:`, and `include_alg:`.

### HTTParty

```ruby
require "httparty"
require "http_signature"

url = "http://example.com/hello"
body = {name: "World"}.to_json
headers = {"Content-Type" => "application/json"}

sig_headers = HTTPSignature.create(
  url:,
  method: "POST",
  headers:,
  key: "MYSECRETKEY",
  key_id: "KEY_1",
  body:
)

HTTParty.post(url, body:, headers: headers.merge(sig_headers))
```

### Excon

```ruby
require "excon"
require "http_signature"

url = "http://example.com/hello"
body = {name: "World"}.to_json
headers = {"Content-Type" => "application/json"}

sig_headers = HTTPSignature.create(
  url:,
  method: "POST",
  headers:,
  key: "MYSECRETKEY",
  key_id: "KEY_1",
  body:
)

Excon.post(url, headers: headers.merge(sig_headers), body:)
```

### Typhoeus

```ruby
require "typhoeus"
require "http_signature"

url = "http://example.com/hello"
body = {name: "World"}.to_json
headers = {"Content-Type" => "application/json"}

sig_headers = HTTPSignature.create(
  url:,
  method: "POST",
  headers:,
  key: "MYSECRETKEY",
  key_id: "KEY_1",
  body:
)

Typhoeus.post(url, body:, headers: headers.merge(sig_headers))
```

## Incoming request examples

### Rack middleware
Rack middlewares sits in between your app and the HTTP request and validate the signature before hitting your app. Read more about [rack middlewares here](https://codenoble.com/blog/understanding-rack-middleware/).

Here is how it could be used with sinatra:

```ruby
require "http_signature/rack"

HTTPSignature.configure do |config|
  config.keys = [
    {id: "key-1", value: "MySecureKey"}
  ]
end
HTTPSignature::Rack.exclude_paths = ["/", "/hello/*"]

use HTTPSignature::Rack
run MyApp
```

### Rails
Opt-in per controller/action using a before_action. It responds with `401 Unauthorized` if the signature is invalid

```ruby
# app/controllers/api/base_controller.rb

require "http_signature/rails"

class Api::BaseController < ApplicationController
  include HTTPSignature::Rails::Controller

  before_action :verify_http_signature!
end
```

Set the keys in an initializer
```ruby
# config/initializers/http_signature.rb

HTTPSignature.configure do |config|
  config.keys = [
    {id: "key-1", value: "MySecureKey"}
  ]
end
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
When you need to make sure that the request or response has not been tampered with (_integrity_). And you can be sure that the request was sent by someone that had the key (_authenticity_). Don't confuse this with encryption, the signed message is not encrypted. It's just _signed_. You could add a layer of encryption on top of this. Or just use HTTPS and you're _kinda safe_ for not that much hassle, which is totally fine in most cases.

[Read more about HMAC here](https://security.stackexchange.com/questions/20129/how-and-when-do-i-use-hmac/20301), even though you can sign your messages with RSA as well, but it's the same principle.

Beware that this has not been audited and should be used at your own risk!
