# frozen_string_literal: true

require_relative "test_helper"
require "./lib/http_signature/faraday"
require "faraday"

describe HTTPSignature::Faraday do
  def hmac_key
    "secret-key"
  end

  it "uses HTTPSignature default components and class-level key configuration" do
    HTTPSignature::Faraday.key = hmac_key
    HTTPSignature::Faraday.key_id = "key-1"

    captured_env = nil
    conn = Faraday.new("http://example.com") do |faraday|
      faraday.use(HTTPSignature::Faraday)
      faraday.adapter(:test) do |stub|
        stub.post("/") do |env|
          captured_env = env
          [200, {}, "ok"]
        end
      end
    end

    conn.post("/") do |req|
      req.headers["Date"] = "Tue, 20 Apr 2021 02:07:55 GMT"
      req.headers["Content-Type"] = "application/json"
      req.body = {message: "hi"}.to_json
    end

    refute_nil captured_env
    signature_input = captured_env[:request_headers]["Signature-Input"]
    assert signature_input
    assert captured_env[:request_headers]["Signature"]
    assert_includes signature_input, 'keyid="key-1"'
    assert_includes signature_input, '"content-type"'
    assert_includes signature_input, '"content-digest"'
    refute_includes signature_input, '"date"'

    assert HTTPSignature.valid?(
      url: "http://example.com/",
      method: :post,
      headers: captured_env[:request_headers],
      body: {message: "hi"}.to_json,
      key: hmac_key
    )
  end

  it "accepts middleware options for key, key_id, and components" do
    captured_env = nil
    conn = Faraday.new("http://example.com") do |faraday|
      faraday.use(
        HTTPSignature::Faraday,
        key: hmac_key,
        key_id: "key-1",
        components: ["@method", "@target-uri", "date", "x-request-id"]
      )
      faraday.adapter(:test) do |stub|
        stub.get("/") do |env|
          captured_env = env
          [200, {}, "ok"]
        end
      end
    end

    conn.get("/") do |req|
      req.headers["Date"] = "Tue, 20 Apr 2021 02:07:55 GMT"
      req.headers["X-Request-Id"] = "req-123"
    end

    refute_nil captured_env
    signature_input = captured_env[:request_headers]["Signature-Input"]
    assert_includes signature_input, '"date"'
    assert_includes signature_input, '"x-request-id"'
    refute_includes signature_input, '"host"'
  end

  it "accepts signature parameter options" do
    created = Time.now.to_i
    expires = created + 600
    captured_env = nil
    conn = Faraday.new("http://example.com") do |faraday|
      faraday.use(
        HTTPSignature::Faraday,
        key: hmac_key,
        key_id: "key-1",
        created:,
        expires:,
        nonce: "abc123",
        tag: "web-bot-auth",
        label: "custom",
        algorithm: "hmac-sha512",
        include_alg: false
      )
      faraday.adapter(:test) do |stub|
        stub.get("/") do |env|
          captured_env = env
          [200, {}, "ok"]
        end
      end
    end

    conn.get("/")

    refute_nil captured_env
    signature_input = captured_env[:request_headers]["Signature-Input"]
    signature = captured_env[:request_headers]["Signature"]

    assert signature_input.start_with?("custom=(")
    assert signature.start_with?("custom=:")
    assert_includes signature_input, "created=#{created}"
    assert_includes signature_input, "expires=#{expires}"
    assert_includes signature_input, 'nonce="abc123"'
    assert_includes signature_input, 'tag="web-bot-auth"'
    refute_includes signature_input, "alg=\"hmac-sha512\""

    assert HTTPSignature.valid?(
      url: "http://example.com/",
      method: :get,
      headers: captured_env[:request_headers],
      key: hmac_key,
      label: "custom",
      algorithm: "hmac-sha512"
    )
  end

  it "ignores nil optional middleware values and keeps HTTPSignature defaults" do
    captured_env = nil
    conn = Faraday.new("http://example.com") do |faraday|
      faraday.use(
        HTTPSignature::Faraday,
        key: hmac_key,
        key_id: "key-1",
        components: nil,
        created: nil,
        expires: nil,
        nonce: nil,
        tag: nil,
        label: nil,
        include_alg: nil,
        algorithm: nil
      )
      faraday.adapter(:test) do |stub|
        stub.post("/") do |env|
          captured_env = env
          [200, {}, "ok"]
        end
      end
    end

    conn.post("/") do |req|
      req.headers["Content-Type"] = "application/json"
      req.body = {message: "hi"}.to_json
    end

    refute_nil captured_env
    signature_input = captured_env[:request_headers]["Signature-Input"]
    signature = captured_env[:request_headers]["Signature"]

    assert signature_input.start_with?("sig1=(")
    assert signature.start_with?("sig1=:")
    assert_includes signature_input, 'alg="hmac-sha256"'
    assert_includes signature_input, '"content-type"'
    assert_includes signature_input, '"content-digest"'

    assert HTTPSignature.valid?(
      url: "http://example.com/",
      method: :post,
      headers: captured_env[:request_headers],
      body: {message: "hi"}.to_json,
      key: hmac_key
    )
  end

  it "accepts per-request tag overrides" do
    HTTPSignature::Faraday.key = hmac_key
    HTTPSignature::Faraday.key_id = "key-1"

    captured_env = nil
    conn = Faraday.new("http://example.com") do |faraday|
      faraday.use(HTTPSignature::Faraday, tag: "default-tag")
      faraday.adapter(:test) do |stub|
        stub.get("/") do |env|
          captured_env = env
          [200, {}, "ok"]
        end
      end
    end

    conn.get("/") do |req|
      req.options.context = {
        http_signature: {
          tag: "request-tag"
        }
      }
    end

    refute_nil captured_env
    signature_input = captured_env[:request_headers]["Signature-Input"]

    assert_includes signature_input, 'tag="request-tag"'
    refute_includes signature_input, 'tag="default-tag"'

    assert HTTPSignature.valid?(
      url: "http://example.com/",
      method: :get,
      headers: captured_env[:request_headers],
      key: hmac_key
    )
  end

  it "accepts per-request key and key_id overrides" do
    HTTPSignature::Faraday.key = "default-secret"
    HTTPSignature::Faraday.key_id = "default-key"

    captured_env = nil
    conn = Faraday.new("http://example.com") do |faraday|
      faraday.use(HTTPSignature::Faraday)
      faraday.adapter(:test) do |stub|
        stub.get("/") do |env|
          captured_env = env
          [200, {}, "ok"]
        end
      end
    end

    conn.get("/") do |req|
      req.options.context = {
        http_signature: {
          key: "request-secret",
          key_id: "request-key"
        }
      }
    end

    refute_nil captured_env
    signature_input = captured_env[:request_headers]["Signature-Input"]
    assert_includes signature_input, 'keyid="request-key"'
    refute_includes signature_input, 'keyid="default-key"'

    assert HTTPSignature.valid?(
      url: "http://example.com/",
      method: :get,
      headers: captured_env[:request_headers],
      key: "request-secret"
    )

    assert_raises(HTTPSignature::SignatureError) do
      HTTPSignature.valid?(
        url: "http://example.com/",
        method: :get,
        headers: captured_env[:request_headers],
        key: "default-secret"
      )
    end
  end

  it "raises when key and key_id are not set" do
    HTTPSignature::Faraday.key = nil
    HTTPSignature::Faraday.key_id = nil

    conn = Faraday.new("http://example.com") do |faraday|
      faraday.use(HTTPSignature::Faraday)
      faraday.adapter(:test) do |stub|
        stub.get("/") { [200, {}, "ok"] }
      end
    end

    assert_raises(RuntimeError) { conn.get("/") }
  end
end
