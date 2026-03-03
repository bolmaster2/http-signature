# frozen_string_literal: true

require "bundler/setup"
require "http_signature"
require "http_signature/faraday"
require "net/http"
require "json"
require "httparty"
require "excon"
require "typhoeus"

BASE = ARGV[0] || "http://localhost:3000"
KEY = "MySecureKey"
KEY_ID = "key-1"

def url_for(path)
  BASE.chomp("/") + path
end

def assert_status(response_code, expected, label)
  if response_code == expected
    puts "✅ #{label}"
    true
  else
    puts "❌ #{label}: expected #{expected}, got #{response_code}"
    false
  end
end

# --- Net::HTTP ---

def net_http_unsigned_rejected
  uri = URI(url_for("/protected"))
  res = Net::HTTP.get_response(uri)
  assert_status(res.code.to_i, 401, "[Net::HTTP] Unsigned request rejected (401)")
end

def net_http_signed_get
  uri = URI(url_for("/protected"))
  sig_headers = HTTPSignature.create(url: uri.to_s, key: KEY, key_id: KEY_ID, method: :get)
  req = Net::HTTP::Get.new(uri)
  sig_headers.each { |k, v| req[k] = v }
  res = Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(req) }
  assert_status(res.code.to_i, 200, "[Net::HTTP] Signed GET accepted (200)")
end

def net_http_signed_post
  uri = URI(url_for("/webhook"))
  body = {event: "user.created", id: 42}.to_json
  headers = {"Content-Type" => "application/json"}
  sig_headers = HTTPSignature.create(
    url: uri.to_s, key: KEY, key_id: KEY_ID, method: :post,
    headers:, body:
  )
  req = Net::HTTP::Post.new(uri)
  headers.merge(sig_headers).each { |k, v| req[k] = v }
  req.body = body
  res = Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(req) }
  assert_status(res.code.to_i, 200, "[Net::HTTP] Signed POST with body accepted (200)")
end

# --- Faraday ---

def faraday_unsigned_rejected
  conn = Faraday.new(url: BASE)
  res = conn.get("/protected")
  assert_status(res.status, 401, "[Faraday] Unsigned request rejected (401)")
end

def faraday_signed_get
  HTTPSignature::Faraday.key = KEY
  HTTPSignature::Faraday.key_id = KEY_ID
  conn = Faraday.new(url: BASE) { |f| f.use HTTPSignature::Faraday }
  res = conn.get("/protected")
  assert_status(res.status, 200, "[Faraday] Signed GET accepted (200)")
end

def faraday_signed_post
  HTTPSignature::Faraday.key = KEY
  HTTPSignature::Faraday.key_id = KEY_ID
  conn = Faraday.new(url: BASE) { |f| f.use HTTPSignature::Faraday }
  res = conn.post("/webhook") do |req|
    req.headers["Content-Type"] = "application/json"
    req.body = {event: "user.created", id: 42}.to_json
  end
  assert_status(res.status, 200, "[Faraday] Signed POST with body accepted (200)")
end

# --- HTTParty ---

def httparty_unsigned_rejected
  res = HTTParty.get(url_for("/protected"))
  assert_status(res.code, 401, "[HTTParty] Unsigned request rejected (401)")
end

def httparty_signed_get
  url = url_for("/protected")
  sig_headers = HTTPSignature.create(url: url, key: KEY, key_id: KEY_ID, method: :get)
  res = HTTParty.get(url, headers: sig_headers)
  assert_status(res.code, 200, "[HTTParty] Signed GET accepted (200)")
end

def httparty_signed_post
  url = url_for("/webhook")
  body = {event: "user.created", id: 42}.to_json
  headers = {"Content-Type" => "application/json"}
  sig_headers = HTTPSignature.create(
    url:, key: KEY, key_id: KEY_ID, method: :post,
    headers:, body:
  )
  res = HTTParty.post(url, headers: headers.merge(sig_headers), body:)
  assert_status(res.code, 200, "[HTTParty] Signed POST with body accepted (200)")
end

# --- Excon ---

def excon_unsigned_rejected
  res = Excon.get(url_for("/protected"))
  assert_status(res.status, 401, "[Excon] Unsigned request rejected (401)")
end

def excon_signed_get
  url = url_for("/protected")
  sig_headers = HTTPSignature.create(url:, key: KEY, key_id: KEY_ID, method: :get)
  res = Excon.get(url, headers: sig_headers)
  assert_status(res.status, 200, "[Excon] Signed GET accepted (200)")
end

def excon_signed_post
  url = url_for("/webhook")
  body = {event: "user.created", id: 42}.to_json
  headers = {"Content-Type" => "application/json"}
  sig_headers = HTTPSignature.create(url:, key: KEY, key_id: KEY_ID, method: :post, headers:, body:)
  res = Excon.post(url, headers: headers.merge(sig_headers), body:)
  assert_status(res.status, 200, "[Excon] Signed POST with body accepted (200)")
end

# --- Typhoeus ---

def typhoeus_unsigned_rejected
  res = Typhoeus.get(url_for("/protected"))
  assert_status(res.code, 401, "[Typhoeus] Unsigned request rejected (401)")
end

def typhoeus_signed_get
  url = url_for("/protected")
  sig_headers = HTTPSignature.create(url:, key: KEY, key_id: KEY_ID, method: :get)
  res = Typhoeus.get(url, headers: sig_headers)
  assert_status(res.code, 200, "[Typhoeus] Signed GET accepted (200)")
end

def typhoeus_signed_post
  url = url_for("/webhook")
  body = {event: "user.created", id: 42}.to_json
  headers = {"Content-Type" => "application/json"}
  sig_headers = HTTPSignature.create(url:, key: KEY, key_id: KEY_ID, method: :post, headers:, body:)
  res = Typhoeus.post(url, headers: headers.merge(sig_headers), body:)
  assert_status(res.code, 200, "[Typhoeus] Signed POST with body accepted (200)")
end

# --- Run all ---

results = [
  net_http_unsigned_rejected,
  net_http_signed_get,
  net_http_signed_post,
  faraday_unsigned_rejected,
  faraday_signed_get,
  faraday_signed_post,
  httparty_unsigned_rejected,
  httparty_signed_get,
  httparty_signed_post,
  excon_unsigned_rejected,
  excon_signed_get,
  excon_signed_post,
  typhoeus_unsigned_rejected,
  typhoeus_signed_get,
  typhoeus_signed_post
]

exit(1) if results.any? { !it }
