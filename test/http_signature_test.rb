# frozen_string_literal: true

require_relative "test_helper"

class HTTPSignatureTest < Minitest::Test
  def key_path(filename)
    File.join(__dir__, "keys", filename)
  end

  # RFC 9421 Appendix B.1.5 - Example Shared Secret
  def shared_secret
    Base64.decode64(File.read(key_path("test_shared_secret.txt")))
  end

  # RFC 9421 Appendix B.1.2 - Example RSA-PSS Key
  def rsa_pss_private_key
    OpenSSL::PKey.read(File.read(key_path("rsa_pss_private_key.pem")))
  end

  def rsa_pss_public_key
    OpenSSL::PKey.read(File.read(key_path("rsa_pss_public_key.pem")))
  end

  # RFC 9421 Appendix B.1.1 - Example RSA Key (for rsa-v1_5-sha256)
  def rsa_private_key
    OpenSSL::PKey.read(File.read(key_path("rsa_private_key.pem")))
  end

  def rsa_public_key
    OpenSSL::PKey.read(File.read(key_path("rsa_public_key.pem")))
  end

  # RFC 9421 Appendix B.1.3 - Example ECC P-256 Test Key
  def ecc_p256_private_key
    OpenSSL::PKey.read(File.read(key_path("ecc_p256_private_key.pem")))
  end

  def ecc_p256_public_key
    OpenSSL::PKey.read(File.read(key_path("ecc_p256_public_key.pem")))
  end

  # RFC 9421 Appendix B.1.4 - Example Ed25519 Test Key
  def ed25519_private_key
    OpenSSL::PKey.read(File.read(key_path("ed25519_private_key.pem")))
  end

  def ed25519_public_key
    OpenSSL::PKey.read(File.read(key_path("ed25519_public_key.pem")))
  end

  # Generate P-384 key for testing (not in RFC examples, but needed for ecdsa-p384-sha384)
  def ecc_p384_private_key
    @ecc_p384_private_key ||= OpenSSL::PKey::EC.generate("secp384r1")
  end

  def ecc_p384_public_key
    ecc_p384_private_key
  end

  # Standard test request from RFC 9421 Appendix B.2
  def default_url
    "https://example.com/foo?param=Value&Pet=dog"
  end

  def default_headers
    {"date" => "Tue, 20 Apr 2021 02:07:55 GMT"}
  end

  def default_body
    '{"hello": "world"}'
  end

  # RFC 9421 Section 3.3.3 - HMAC Using SHA-256
  def test_hmac_sha256
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-shared-secret",
      key: shared_secret,
      algorithm: "hmac-sha256",
      covered_components: %w[@method @authority @target-uri date],
      created: 1_618_884_473
    )

    assert sig_headers["Signature-Input"]
    assert sig_headers["Signature"]

    headers = default_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers:,
      key: shared_secret
    )
  end

  # RFC 9421 Section 3.3.1 - RSASSA-PSS Using SHA-512
  def test_rsa_pss_sha512
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      body: default_body,
      key_id: "test-key-rsa-pss",
      key: rsa_pss_private_key,
      algorithm: "rsa-pss-sha512",
      covered_components: %w[@method @authority @path],
      created: 1_618_884_473
    )

    assert sig_headers["Signature-Input"]
    assert sig_headers["Signature"]

    headers = default_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers:,
      body: default_body,
      key: rsa_pss_public_key
    )
  end

  # RFC 9421 Section 3.3.2 - RSASSA-PKCS1-v1_5 Using SHA-256
  def test_rsa_v1_5_sha256
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-key-rsa",
      key: rsa_private_key,
      algorithm: "rsa-v1_5-sha256",
      covered_components: %w[@method @authority @path],
      created: 1_618_884_480
    )

    assert sig_headers["Signature-Input"]
    assert sig_headers["Signature"]

    headers = default_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers:,
      key: rsa_public_key
    )
  end

  # RFC 9421 Section 3.3.4 - ECDSA Using Curve P-256 DSS and SHA-256
  def test_ecdsa_p256_sha256
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-key-ecc-p256",
      key: ecc_p256_private_key,
      algorithm: "ecdsa-p256-sha256",
      covered_components: %w[@method @authority @path],
      created: 1_618_884_473
    )

    assert sig_headers["Signature-Input"]
    assert sig_headers["Signature"]

    headers = default_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers:,
      key: ecc_p256_public_key
    )
  end

  # RFC 9421 Section 3.3.5 - ECDSA Using Curve P-384 DSS and SHA-384
  def test_ecdsa_p384_sha384
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-key-ecc-p384",
      key: ecc_p384_private_key,
      algorithm: "ecdsa-p384-sha384",
      covered_components: %w[@method @authority @path],
      created: 1_618_884_473
    )

    assert sig_headers["Signature-Input"]
    assert sig_headers["Signature"]

    headers = default_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers:,
      key: ecc_p384_public_key
    )
  end

  # RFC 9421 Section 3.3.6 - EdDSA Using Curve edwards25519
  def test_ed25519
    headers = {
      "date" => "Tue, 20 Apr 2021 02:07:55 GMT",
      "content-type" => "application/json",
      "content-length" => "18"
    }

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers:,
      key_id: "test-key-ed25519",
      key: ed25519_private_key,
      algorithm: "ed25519",
      covered_components: %w[date @method @path @authority content-type content-length],
      created: 1_618_884_473
    )

    assert sig_headers["Signature-Input"]
    assert sig_headers["Signature"]

    signed_headers = headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers: signed_headers,
      key: ed25519_public_key
    )
  end

  def test_adds_content_digest_when_body_present
    body = '{"hello":"world"}'
    headers = {}
    url = "https://example.com/submit"

    sig_headers = HTTPSignature.create(
      url:,
      method: :post,
      headers:,
      body:,
      key_id: "test",
      key: shared_secret
    )

    assert_includes sig_headers["Signature-Input"], "content-digest"
  end

  def test_signature_input_escapes_structured_values
    key_id = 'key"id\\with\\backslash'
    nonce = 'nonce"value\\and\\more'

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id:,
      key: shared_secret,
      nonce:,
      covered_components: %w[@method],
      created: 1
    )

    sig_input = sig_headers.fetch("Signature-Input")

    assert_includes sig_input, 'keyid="key\"id\\\\with\\\\backslash"'
    assert_includes sig_input, 'nonce="nonce\"value\\\\and\\\\more"'
  end

  def test_raises_when_required_header_missing
    assert_raises(HTTPSignature::MissingComponent) do
      HTTPSignature.create(
        url: "https://example.com/test",
        method: :get,
        headers: {},
        key: shared_secret,
        key_id: "test",
        covered_components: %w[date]
      )
    end
  end

  def test_rejects_tampered_signature_hmac
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-shared-secret",
      key: shared_secret,
      algorithm: "hmac-sha256",
      covered_components: %w[@method @authority]
    )

    headers = default_headers.merge(sig_headers)

    refute HTTPSignature.valid?(
      url: default_url,
      method: :get, # Changed from :post
      headers:,
      key: shared_secret
    )
  end

  def test_rejects_wrong_key_ecdsa_p256
    other_key = OpenSSL::PKey::EC.generate("prime256v1")

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-key-ecc-p256",
      key: ecc_p256_private_key,
      algorithm: "ecdsa-p256-sha256",
      covered_components: %w[@method @authority]
    )

    headers = default_headers.merge(sig_headers)

    refute HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers:,
      key: other_key
    )
  end

  def test_rejects_wrong_key_ed25519
    other_key = OpenSSL::PKey.generate_key("ED25519")

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-key-ed25519",
      key: ed25519_private_key,
      algorithm: "ed25519",
      covered_components: %w[@method @authority]
    )

    headers = default_headers.merge(sig_headers)

    refute HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers:,
      key: other_key
    )
  end

  def test_raises_on_unsupported_algorithm
    assert_raises(HTTPSignature::UnsupportedAlgorithm) do
      HTTPSignature.create(
        url: default_url,
        method: :get,
        headers: {},
        key: "key",
        key_id: "test",
        algorithm: "unknown-algorithm"
      )
    end
  end
end
