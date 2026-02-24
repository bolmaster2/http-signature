# frozen_string_literal: true

require_relative "test_helper"
require "./lib/http_signature/rack"
require "rack/mock"

describe HTTPSignature::Rack do
  def hmac_key
    "secret-key"
  end

  it "verifies an incoming request with valid signature" do
    HTTPSignature.configure do |config|
      config.keys = [{id: "key-1", value: hmac_key}]
    end
    date = "Tue, 20 Apr 2021 02:07:55 GMT"
    url = "http://example.com/hello?pet=dog"

    sig_headers = HTTPSignature.create(
      url: url,
      method: :get,
      headers: {"date" => date},
      key_id: "key-1",
      key: hmac_key,
      components: %w[@method @authority @target-uri date],
      created: 1_618_884_473
    )

    app = ->(_env) { [200, {"Content-Type" => "text/plain"}, ["ok"]] }
    middleware = HTTPSignature::Rack.new(app)
    request = Rack::MockRequest.new(middleware)

    response = request.get(
      "/hello?pet=dog",
      "HTTP_HOST" => "example.com",
      "HTTP_DATE" => date,
      "HTTP_SIGNATURE_INPUT" => sig_headers["Signature-Input"],
      "HTTP_SIGNATURE" => sig_headers["Signature"]
    )

    assert_equal 200, response.status
    assert_equal "ok", response.body
  end

  it "verifies a request signed with content-type component" do
    HTTPSignature.configure do |config|
      config.keys = [{id: "key-1", value: hmac_key}]
    end
    url = "http://example.com/submit"
    body = '{"hello":"world"}'

    sig_headers = HTTPSignature.create(
      url: url,
      method: :post,
      headers: {"content-type" => "application/json"},
      body: body,
      key_id: "key-1",
      key: hmac_key,
      components: %w[@method content-type content-digest],
      created: 1_618_884_473
    )

    app = ->(_env) { [200, {"Content-Type" => "text/plain"}, ["ok"]] }
    middleware = HTTPSignature::Rack.new(app)
    request = Rack::MockRequest.new(middleware)

    response = request.post(
      "/submit",
      "HTTP_HOST" => "example.com",
      "CONTENT_TYPE" => "application/json",
      "HTTP_SIGNATURE_INPUT" => sig_headers["Signature-Input"],
      "HTTP_SIGNATURE" => sig_headers["Signature"],
      input: body
    )

    assert_equal 200, response.status, "Expected 200 but got #{response.status}: #{response.body}"
  end

  it "rejects requests with no signature headers" do
    app = ->(_env) { [200, {"Content-Type" => "text/plain"}, ["ok"]] }
    middleware = HTTPSignature::Rack.new(app)
    request = Rack::MockRequest.new(middleware)

    response = request.get("/hello", "HTTP_HOST" => "example.com")

    assert_equal 401, response.status
    assert_equal "No signature header", response.body
  end

  it "rejects requests with an invalid signature" do
    HTTPSignature.configure do |config|
      config.keys = [{id: "key-1", value: hmac_key}]
    end

    app = ->(_env) { [200, {"Content-Type" => "text/plain"}, ["ok"]] }
    middleware = HTTPSignature::Rack.new(app)
    request = Rack::MockRequest.new(middleware)

    response = request.get(
      "/hello",
      "HTTP_HOST" => "example.com",
      "HTTP_SIGNATURE_INPUT" => 'sig1=("@method");created=1;keyid="key-1"',
      "HTTP_SIGNATURE" => "sig1=:aW52YWxpZA==:"
    )

    assert_equal 401, response.status
    assert_equal "Invalid signature", response.body
  end

  it "skips verification for excluded paths" do
    HTTPSignature::Rack.exclude_paths = [/\A\/health/]

    app = ->(_env) { [200, {"Content-Type" => "text/plain"}, ["ok"]] }
    middleware = HTTPSignature::Rack.new(app)
    request = Rack::MockRequest.new(middleware)

    response = request.get("/health", "HTTP_HOST" => "example.com")

    assert_equal 200, response.status
    assert_equal "ok", response.body
  ensure
    HTTPSignature::Rack.exclude_paths = []
  end
end
