# frozen_string_literal: true

require_relative "../test_helper"
require "base64"
require "json"
require "net/http"

# See https://http-message-signatures-example.research.cloudflare.com
class CloudflareExampleResearchTest < Minitest::Test
  BASE_URL = "https://http-message-signatures-example.research.cloudflare.com"
  DIRECTORY_URL = "#{BASE_URL}/.well-known/http-message-signatures-directory"
  SUCCESS_TEXT = "You successfully authenticated as owning the test public key"
  FAILURE_TEXT = "The Signature you sent does not validate against test public key"
  CLOUDFLARE_TAG = "web-bot-auth"
  NETWORK_ERRORS = [
    EOFError,
    Errno::ECONNREFUSED,
    Errno::ECONNRESET,
    Errno::EHOSTUNREACH,
    JSON::ParserError,
    Net::OpenTimeout,
    Net::ReadTimeout,
    OpenSSL::SSL::SSLError,
    SocketError
  ].freeze

  def test_root_authenticates_with_matching_private_key
    directory_key = cloudflare_directory_key
    assert_equal bundled_public_jwk_x, directory_key.fetch("x")

    response = perform_signed_request(key: ed25519_private_key, key_id: directory_key.fetch("kid"))
    body = response.body.to_s

    assert_equal "200", response.code
    assert_includes body, SUCCESS_TEXT
    refute_includes body, FAILURE_TEXT
  rescue *NETWORK_ERRORS => e
    skip "Cloudflare example unavailable: #{e.class}: #{e.message}"
  end

  def test_root_rejects_a_wrong_private_key
    directory_key = cloudflare_directory_key
    response = perform_signed_request(key: OpenSSL::PKey.generate_key("ED25519"), key_id: directory_key.fetch("kid"))
    body = response.body.to_s

    assert_equal "200", response.code
    refute_includes body, SUCCESS_TEXT
    assert_includes body, FAILURE_TEXT
  rescue *NETWORK_ERRORS => e
    skip "Cloudflare example unavailable: #{e.class}: #{e.message}"
  end

  private

  def perform_signed_request(key:, key_id:)
    uri = URI("#{BASE_URL}/")
    request = Net::HTTP::Get.new(uri)
    request_headers(uri).merge(cloudflare_signature_headers(uri:, key:, key_id:)).each do |header, value|
      request[header] = value
    end

    perform_request(uri, request)
  end

  def cloudflare_signature_headers(uri:, key:, key_id:)
    HTTPSignature.create(
      url: uri.to_s,
      key:,
      key_id:,
      method: :get,
      headers: request_headers(uri),
      algorithm: "ed25519",
      components: %w[@authority signature-agent],
      expires: Time.now.to_i + 500,
      tag: CLOUDFLARE_TAG
    )
  end

  def request_headers(uri)
    {
      "signature-agent" => uri.to_s,
      "user-agent" => "http_signature/#{HTTPSignature::VERSION}"
    }
  end

  def perform_request(uri, request)
    Net::HTTP.start(
      uri.host,
      uri.port,
      use_ssl: uri.scheme == "https",
      open_timeout: 10,
      read_timeout: 10
    ) do |http|
      http.request(request)
    end
  end

  def cloudflare_directory_key
    @cloudflare_directory_key ||= begin
      uri = URI(DIRECTORY_URL)
      response = perform_request(uri, Net::HTTP::Get.new(uri))
      JSON.parse(response.body).fetch("keys").first
    end
  end

  def ed25519_private_key
    OpenSSL::PKey.read(File.read(key_path("ed25519_private_key.pem")))
  end

  def bundled_public_jwk_x
    public_key = OpenSSL::PKey.read(File.read(key_path("ed25519_public_key.pem")))
    Base64.urlsafe_encode64(public_key.public_to_der[-32, 32], padding: false)
  end

  def key_path(filename)
    File.join(__dir__, "..", "keys", filename)
  end
end
