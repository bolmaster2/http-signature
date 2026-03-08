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

  # RFC 9421 Appendix B.2.5 - Signing a Request Using hmac-sha256
  # HMAC is deterministic, so signature must match exactly.
  def test_hmac_sha256
    headers = {
      "date" => "Tue, 20 Apr 2021 02:07:55 GMT",
      "content-type" => "application/json"
    }

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers:,
      key_id: "test-shared-secret",
      key: shared_secret,
      algorithm: "hmac-sha256",
      components: %w[date @authority content-type],
      created: 1_618_884_473,
      label: "sig-b25",
      include_alg: false # RFC example doesn't include alg parameter
    )

    # RFC 9421 Appendix B.2.5 expected values
    expected_signature_input = '("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"'
    expected_signature = "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8="

    assert_equal "sig-b25=#{expected_signature_input}", sig_headers["Signature-Input"]
    assert_equal "sig-b25=:#{expected_signature}:", sig_headers["Signature"]

    signed_headers = headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers: signed_headers,
      key: shared_secret,
      label: "sig-b25"
    )
  end

  # RFC 9421 Appendix B.2.3 - Full Coverage Using rsa-pss-sha512
  # RSA-PSS is non-deterministic, so we verify Signature-Input matches exactly
  # and that the signature validates correctly.
  def test_rsa_pss_sha512
    headers = {
      "date" => "Tue, 20 Apr 2021 02:07:55 GMT",
      "content-type" => "application/json",
      "content-digest" => "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
      "content-length" => "18"
    }

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers:,
      key_id: "test-key-rsa-pss",
      key: rsa_pss_private_key,
      algorithm: "rsa-pss-sha512",
      components: %w[date @method @path @query @authority content-type content-digest content-length],
      created: 1_618_884_473,
      label: "sig-b23",
      include_alg: false # RFC example doesn't include alg parameter
    )

    # RFC 9421 Appendix B.2.3 expected Signature-Input (alg not included in RFC example)
    expected_signature_input = '("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"'

    assert_equal "sig-b23=#{expected_signature_input}", sig_headers["Signature-Input"]
    assert sig_headers["Signature"]

    signed_headers = headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers: signed_headers,
      key: rsa_pss_public_key,
      label: "sig-b23",
      algorithm: "rsa-pss-sha512"
    )
  end

  # RFC 9421 Section 3.3.2 - RSASSA-PKCS1-v1_5 Using SHA-256
  # This algorithm is defined in RFC but not in test cases B.2, so we just verify it works.
  def test_rsa_v1_5_sha256
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-key-rsa",
      key: rsa_private_key,
      algorithm: "rsa-v1_5-sha256",
      components: %w[@method @authority @path],
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

  # RFC 9421 Appendix B.2.4 - Signing a Response Using ecdsa-p256-sha256
  # ECDSA is non-deterministic, so we verify Signature-Input matches exactly
  # and that the signature validates correctly.
  def test_ecdsa_p256_sha256
    response_headers = {
      "date" => "Tue, 20 Apr 2021 02:07:56 GMT",
      "content-type" => "application/json",
      "content-digest" => "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:",
      "content-length" => "23"
    }

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: response_headers,
      key_id: "test-key-ecc-p256",
      key: ecc_p256_private_key,
      algorithm: "ecdsa-p256-sha256",
      components: %w[@status content-type content-digest content-length],
      created: 1_618_884_473,
      label: "sig-b24",
      include_alg: false, # RFC example doesn't include alg parameter
      status: 200
    )

    # RFC 9421 Appendix B.2.4 expected Signature-Input
    expected_signature_input = '("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"'

    assert_equal "sig-b24=#{expected_signature_input}", sig_headers["Signature-Input"]
    assert sig_headers["Signature"]

    signed_headers = response_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers: signed_headers,
      key: ecc_p256_public_key,
      label: "sig-b24",
      algorithm: "ecdsa-p256-sha256",
      status: 200
    )
  end

  # RFC 9421 Section 3.3.5 - ECDSA Using Curve P-384 DSS and SHA-384
  # This algorithm is defined in RFC but not in test cases B.2, so we just verify it works.
  def test_ecdsa_p384_sha384
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-key-ecc-p384",
      key: ecc_p384_private_key,
      algorithm: "ecdsa-p384-sha384",
      components: %w[@method @authority @path],
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

  # RFC 9421 Appendix B.2.6 - Signing a Request Using ed25519
  # This test verifies exact signature output matches the RFC test vector.
  # Ed25519 is deterministic, so signatures must match exactly.
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
      components: %w[date @method @path @authority content-type content-length],
      created: 1_618_884_473,
      label: "sig-b26",
      include_alg: false # RFC example doesn't include alg parameter
    )

    # RFC 9421 Appendix B.2.6 expected values
    expected_signature_input = '("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"'
    expected_signature = "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=="

    assert_equal "sig-b26=#{expected_signature_input}", sig_headers["Signature-Input"]
    assert_equal "sig-b26=:#{expected_signature}:", sig_headers["Signature"]

    signed_headers = headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers: signed_headers,
      key: ed25519_public_key,
      label: "sig-b26",
      algorithm: "ed25519"
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

  def test_adds_content_digest_when_component_explicitly_requested
    body = default_body

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      body:,
      key_id: "test-shared-secret",
      key: shared_secret,
      components: %w[@method content-digest]
    )

    assert_includes sig_headers["Signature-Input"], "content-digest"
  end

  def test_defaults_components_and_headers_when_not_provided
    headers = {"content-type" => "application/json"}
    body = default_body

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers:,
      body:,
      key_id: "test-shared-secret",
      key: shared_secret
    )

    component_section = sig_headers.fetch("Signature-Input")[/\(([^)]*)\)/, 1]
    components = component_section.split.map { |c| c.delete_prefix('"').delete_suffix('"') }

    assert_equal %w[@method @target-uri content-digest content-type], components
  end

  def test_merges_url_and_query_string_params_into_signature
    url = "https://example.com/foo?pet=dog"
    query_string_params = {pet2: "cat"}

    sig_headers = HTTPSignature.create(
      url:,
      key_id: "test-shared-secret",
      key: shared_secret,
      query_string_params:
    )

    headers = default_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url:,
      method: :get,
      headers:,
      key: shared_secret,
      query_string_params:
    )

    assert_raises(HTTPSignature::SignatureError) do
      HTTPSignature.valid?(
        url:,
        method: :get,
        headers:,
        key: shared_secret
      )
    end
  end

  def test_signature_input_escapes_structured_values
    key_id = 'key"id\\with\\backslash'
    nonce = 'nonce"value\\and\\more'
    tag = 'tag"value\\and\\more'

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id:,
      key: shared_secret,
      nonce:,
      tag:,
      components: %w[@method],
      created: 1
    )

    sig_input = sig_headers.fetch("Signature-Input")

    assert_includes sig_input, 'keyid="key\"id\\\\with\\\\backslash"'
    assert_includes sig_input, 'nonce="nonce\"value\\\\and\\\\more"'
    assert_includes sig_input, 'tag="tag\"value\\\\and\\\\more"'
  end

  def test_roundtrip_with_special_characters_in_key_id
    key_id = 'key"with"quotes'

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id:,
      key: shared_secret,
      components: %w[@method],
      created: 1
    )

    headers = default_headers.merge(sig_headers)

    resolved_key_id = nil
    resolver = ->(kid) {
      resolved_key_id = kid
      shared_secret
    }

    begin
      HTTPSignature.valid?(
        url: default_url,
        method: :post,
        headers:,
        key_resolver: resolver
      )
    rescue HTTPSignature::SignatureError
      # Signature fails because corrupted key_id also corrupts the base string
    end

    assert_equal key_id, resolved_key_id,
      "key_id should round-trip through create/parse: expected #{key_id.inspect}, got #{resolved_key_id.inspect}"
  end

  def test_signature_input_includes_expires_param
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-shared-secret",
      key: shared_secret,
      components: %w[@method],
      created: 1,
      expires: 61
    )

    sig_input = sig_headers.fetch("Signature-Input")

    assert_includes sig_input, "expires=61"
  end

  def test_create_raises_when_created_is_after_expires
    assert_raises(ArgumentError) do
      HTTPSignature.create(
        url: default_url,
        key_id: "test-shared-secret",
        key: shared_secret,
        created: 20,
        expires: 10
      )
    end
  end

  def test_create_raises_when_timestamps_are_not_integers
    assert_raises(ArgumentError) do
      HTTPSignature.create(
        url: default_url,
        key_id: "test-shared-secret",
        key: shared_secret,
        created: "not-a-timestamp"
      )
    end

    assert_raises(ArgumentError) do
      HTTPSignature.create(
        url: default_url,
        key_id: "test-shared-secret",
        key: shared_secret,
        expires: Time.now.to_f.to_i + 10.5
      )
    end
  end

  def test_valid_raises_when_max_age_is_not_a_non_negative_integer
    sig_headers = HTTPSignature.create(
      url: default_url,
      key_id: "test-shared-secret",
      key: shared_secret,
      components: %w[@method]
    )

    headers = default_headers.merge(sig_headers)

    assert_raises(ArgumentError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :get,
        headers:,
        key: shared_secret,
        max_age: "60"
      )
    end

    assert_raises(ArgumentError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :get,
        headers:,
        key: shared_secret,
        max_age: -1
      )
    end
  end

  def test_valid_raises_when_created_parameter_is_missing
    sig_headers = HTTPSignature.create(
      url: default_url,
      key_id: "test-shared-secret",
      key: shared_secret,
      components: %w[@method]
    )
    tampered_signature_input = sig_headers.fetch("Signature-Input").sub(/;created=\d+/, "")
    headers = default_headers.merge(sig_headers.merge("Signature-Input" => tampered_signature_input))

    assert_raises(HTTPSignature::SignatureError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :get,
        headers:,
        key: shared_secret
      )
    end
  end

  def test_valid_raises_when_created_parameter_is_non_numeric
    sig_headers = HTTPSignature.create(
      url: default_url,
      key_id: "test-shared-secret",
      key: shared_secret,
      components: %w[@method]
    )
    tampered_signature_input = sig_headers.fetch("Signature-Input").sub(/created=\d+/, "created=not-a-number")
    headers = default_headers.merge(sig_headers.merge("Signature-Input" => tampered_signature_input))

    assert_raises(HTTPSignature::SignatureError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :get,
        headers:,
        key: shared_secret
      )
    end
  end

  def test_rejects_expired_signature
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-shared-secret",
      key: shared_secret,
      components: %w[@method],
      created: 1,
      expires: 5
    )

    headers = default_headers.merge(sig_headers)

    assert_raises(HTTPSignature::ExpiredError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :post,
        headers:,
        key: shared_secret
      )
    end
  end

  def test_expired_when_now_is_after_expires
    expires = Time.now.to_i - 60

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-shared-secret",
      key: shared_secret,
      components: %w[@method],
      created: expires - 5,
      expires:
    )

    headers = default_headers.merge(sig_headers)

    assert_raises(HTTPSignature::ExpiredError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :post,
        headers:,
        key: shared_secret
      )
    end
  end

  def test_max_age_rejects_old_signature
    created = Time.now.to_i - 120

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-shared-secret",
      key: shared_secret,
      components: %w[@method],
      created:
    )

    headers = default_headers.merge(sig_headers)

    assert_raises(HTTPSignature::ExpiredError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :post,
        headers:,
        key: shared_secret,
        max_age: 60
      )
    end
  end

  def test_max_age_accepts_recent_signature
    created = Time.now.to_i - 30

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-shared-secret",
      key: shared_secret,
      components: %w[@method],
      created:
    )

    headers = default_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers:,
      key: shared_secret,
      max_age: 60
    )
  end

  def test_max_age_takes_precedence_over_signature_expires
    created = Time.now.to_i - 30
    expires = Time.now.to_i + 3600 # Signature says it's valid for another hour

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-shared-secret",
      key: shared_secret,
      components: %w[@method],
      created:,
      expires:
    )

    headers = default_headers.merge(sig_headers)

    # Should be rejected because max_age (10 seconds) takes precedence
    # and the signature was created 30 seconds ago
    assert_raises(HTTPSignature::ExpiredError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :post,
        headers:,
        key: shared_secret,
        max_age: 10
      )
    end
  end

  def test_raises_when_required_header_missing
    assert_raises(HTTPSignature::MissingComponent) do
      HTTPSignature.create(
        url: "https://example.com/test",
        method: :get,
        headers: {},
        key: shared_secret,
        key_id: "test",
        components: %w[date]
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
      components: %w[@method @authority]
    )

    headers = default_headers.merge(sig_headers)

    assert_raises(HTTPSignature::SignatureError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :get, # Changed from :post
        headers:,
        key: shared_secret
      )
    end
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
      components: %w[@method @authority]
    )

    headers = default_headers.merge(sig_headers)

    assert_raises(HTTPSignature::SignatureError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :post,
        headers:,
        key: other_key
      )
    end
  end

  def test_rejects_malformed_ecdsa_signature_length
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-key-ecc-p256",
      key: ecc_p256_private_key,
      algorithm: "ecdsa-p256-sha256",
      components: %w[@method @authority]
    )
    malformed_signature = "sig1=:#{Base64.strict_encode64("short-signature")}:"
    headers = default_headers.merge(sig_headers.merge("Signature" => malformed_signature))

    assert_raises(HTTPSignature::SignatureError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :post,
        headers:,
        key: ecc_p256_public_key,
        algorithm: "ecdsa-p256-sha256"
      )
    end
  end

  def test_rejects_algorithm_confusion_attack
    # Generate an HMAC signature using the RSA public key as the HMAC secret manually
    # to bypass the protection in `create` which we just added.

    url = default_url
    method = :post
    headers = default_headers
    key_id = "test-key-rsa"
    # Attack: Using public key as HMAC secret
    attack_secret = rsa_public_key.to_pem

    # We stub asymmetric_key? to return false temporarily so we can create the attack signature
    original_method = HTTPSignature.method(:asymmetric_key?)
    original_verbose = $VERBOSE
    begin
      $VERBOSE = nil
      HTTPSignature.define_singleton_method(:asymmetric_key?) { |key| false }
      $VERBOSE = original_verbose

      sig_headers = HTTPSignature.create(
        url:,
        method:,
        headers:,
        key_id:,
        key: attack_secret,
        algorithm: "hmac-sha256",
        components: %w[@method @authority @path],
        created: 1_618_884_480
      )
    ensure
      $VERBOSE = nil
      HTTPSignature.define_singleton_method(:asymmetric_key?, original_method)
      $VERBOSE = original_verbose
    end

    headers = default_headers.merge(sig_headers)

    # The server expects RSA verification with the public key
    assert_raises(HTTPSignature::SignatureError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :post,
        headers:,
        key: rsa_public_key,
        # Server expects RSA, but the attacker's signature specifies hmac-sha256.
        # If the library trusts the attacker's alg, it might use the RSA public key
        # as an HMAC secret, which would succeed if not protected!
        algorithm: "rsa-v1_5-sha256" # If server forces this, it fails.
      )
    end

    # What if the server DOES NOT force the algorithm?
    # This should now also raise SignatureError because verify_signature prevents HMAC + Asymmetric key
    error = assert_raises(HTTPSignature::SignatureError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :post,
        headers:,
        key: attack_secret, # Server passes public key as PEM string
        algorithm: nil # Library infers algorithm from signature parameters
      )
    end

    assert_equal "HMAC algorithm cannot be used with an asymmetric key", error.message
  end

  def test_rejects_mismatched_content_digest
    body = '{"hello":"world"}'
    digest = Digest::SHA256.digest(body)
    content_digest = "sha-256=:#{Base64.strict_encode64(digest)}:"
    headers = {"content-type" => "application/json", "content-digest" => content_digest}

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers:,
      body:,
      key_id: "test",
      key: shared_secret,
      components: %w[content-digest]
    )

    signed_headers = headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers: signed_headers,
      body:,
      key: shared_secret
    )

    malicious_body = '{"hello":"attacker"}'
    assert_raises(HTTPSignature::SignatureError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :post,
        headers: signed_headers,
        body: malicious_body,
        key: shared_secret
      )
    end
  end

  def test_verify_raises_when_content_digest_header_missing_but_component_signed
    body = '{"hello":"world"}'
    headers = {"content-type" => "application/json"}

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers:,
      body:,
      key_id: "test",
      key: shared_secret,
      components: %w[@method content-digest]
    )

    signed_headers = headers.merge(sig_headers)
    signed_headers.delete("Content-Digest")
    signed_headers.delete("content-digest")

    error = assert_raises(HTTPSignature::MissingComponent) do
      HTTPSignature.valid?(
        url: default_url,
        method: :post,
        headers: signed_headers,
        body:,
        key: shared_secret
      )
    end

    assert_equal "Missing required component: content-digest", error.message
  end

  def test_verify_fails_when_content_digest_header_stripped_and_body_tampered
    body = '{"hello":"world"}'
    headers = {"content-type" => "application/json"}

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers:,
      body:,
      key_id: "test",
      key: shared_secret,
      components: %w[@method content-digest]
    )

    signed_headers = headers.merge(sig_headers)
    signed_headers.delete("Content-Digest")
    signed_headers.delete("content-digest")

    # Even though the header is stripped, the regenerated digest won't match
    # what was signed because the body has changed.
    assert_raises(HTTPSignature::SignatureError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :post,
        headers: signed_headers,
        body: '{"hello":"attacker"}',
        key: shared_secret
      )
    end
  end

  def test_verify_rejects_unsupported_content_digest_algorithm
    body = '{"hello":"world"}'
    headers = {"content-type" => "application/json"}

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers:,
      body:,
      key_id: "test",
      key: shared_secret,
      components: %w[@method content-digest]
    )

    signed_headers = headers.merge(sig_headers)
    signed_headers["content-digest"] = "md5=:rL0Y20zC+Fzt72VPzMSk2A==:"

    error = assert_raises(HTTPSignature::SignatureError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :post,
        headers: signed_headers,
        body:,
        key: shared_secret
      )
    end

    assert_equal "Content-Digest header contains no supported algorithm", error.message
  end

  def test_verify_rejects_malformed_content_digest_encoding
    body = '{"hello":"world"}'
    digest = Digest::SHA256.digest(body)
    content_digest = "sha-256=:#{Base64.strict_encode64(digest)}:"
    headers = {"content-type" => "application/json", "content-digest" => content_digest}

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers:,
      body:,
      key_id: "test",
      key: shared_secret,
      components: %w[@method content-digest]
    )

    signed_headers = headers.merge(sig_headers)
    signed_headers["content-digest"] = "sha-256=:notvalid===base64:"

    error = assert_raises(HTTPSignature::SignatureError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :post,
        headers: signed_headers,
        body:,
        key: shared_secret
      )
    end

    assert_equal "Invalid Content-Digest encoding for sha-256", error.message
  end

  def test_verify_content_digest_with_sha512
    body = '{"hello":"world"}'
    headers = {"content-type" => "application/json"}
    digest = Digest::SHA512.digest(body)
    content_digest = "sha-512=:#{Base64.strict_encode64(digest)}:"

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: headers.merge("content-digest" => content_digest),
      body:,
      key_id: "test",
      key: shared_secret,
      components: %w[@method content-digest]
    )

    signed_headers = headers.merge("content-digest" => content_digest).merge(sig_headers)

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers: signed_headers,
      body:,
      key: shared_secret
    )
  end

  def test_verify_rejects_missing_content_digest_when_required
    body = '{"hello":"world"}'
    headers = {"content-type" => "application/json"}

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers:,
      body: "",
      key_id: "test",
      key: shared_secret,
      components: %w[@method content-type]
    )

    signed_headers = headers.merge(sig_headers)

    error = assert_raises(HTTPSignature::SignatureError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :post,
        headers: signed_headers,
        body:,
        key: shared_secret,
        require_content_digest: true
      )
    end

    assert_match(/content-digest/, error.message.downcase)
  end

  def test_verify_allows_missing_content_digest_by_default
    headers = {"content-type" => "application/json"}

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers:,
      body: "",
      key_id: "test",
      key: shared_secret,
      components: %w[@method content-type]
    )

    signed_headers = headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers: signed_headers,
      body: "",
      key: shared_secret
    )
  end

  def test_hmac_validation_uses_secure_compare
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-shared-secret",
      key: shared_secret,
      algorithm: "hmac-sha256",
      components: %w[@method @authority]
    )
    headers = default_headers.merge(sig_headers)
    secure_compare_called = false
    original = OpenSSL.method(:fixed_length_secure_compare)
    original_verbose = $VERBOSE

    $VERBOSE = nil
    OpenSSL.define_singleton_method(:fixed_length_secure_compare) do |a, b|
      secure_compare_called = true
      original.call(a, b)
    end

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers:,
      key: shared_secret
    )
    assert secure_compare_called
  ensure
    if original
      $VERBOSE = nil
      OpenSSL.define_singleton_method(:fixed_length_secure_compare, original)
      $VERBOSE = original_verbose
    end
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
      components: %w[@method @authority]
    )

    headers = default_headers.merge(sig_headers)

    assert_raises(HTTPSignature::SignatureError) do
      HTTPSignature.valid?(
        url: default_url,
        method: :post,
        headers:,
        key: other_key
      )
    end
  end

  # -- #10: Derived component edge cases --

  def test_query_component_with_no_query_string
    url = "https://example.com/foo"

    sig_headers = HTTPSignature.create(
      url:,
      method: :get,
      headers: default_headers,
      key_id: "test",
      key: shared_secret,
      components: %w[@method @query],
      created: 1
    )

    assert_includes sig_headers["Signature-Input"], '"@query"'

    headers = default_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url:,
      method: :get,
      headers:,
      key: shared_secret
    )
  end

  def test_path_component_with_empty_path
    url = "https://example.com"

    sig_headers = HTTPSignature.create(
      url:,
      method: :get,
      headers: default_headers,
      key_id: "test",
      key: shared_secret,
      components: %w[@method @path],
      created: 1
    )

    headers = default_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url:,
      method: :get,
      headers:,
      key: shared_secret
    )
  end

  def test_authority_component_with_non_standard_port
    url = "https://example.com:8443/foo"

    sig_headers = HTTPSignature.create(
      url:,
      method: :get,
      headers: default_headers,
      key_id: "test",
      key: shared_secret,
      components: %w[@method @authority],
      created: 1
    )

    assert_includes sig_headers["Signature-Input"], '"@authority"'

    headers = default_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url:,
      method: :get,
      headers:,
      key: shared_secret
    )
  end

  def test_scheme_component
    url = "https://example.com/foo"

    sig_headers = HTTPSignature.create(
      url:,
      method: :get,
      headers: default_headers,
      key_id: "test",
      key: shared_secret,
      components: %w[@method @scheme],
      created: 1
    )

    assert_includes sig_headers["Signature-Input"], '"@scheme"'

    headers = default_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url:,
      method: :get,
      headers:,
      key: shared_secret
    )
  end

  # -- #11: key_resolver callback --

  def test_key_resolver_is_called_with_key_id
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :get,
      headers: default_headers,
      key_id: "my-key-id",
      key: shared_secret,
      components: %w[@method]
    )

    headers = default_headers.merge(sig_headers)

    resolved_key_id = nil
    assert HTTPSignature.valid?(
      url: default_url,
      method: :get,
      headers:,
      key_resolver: ->(kid) {
        resolved_key_id = kid
        shared_secret
      }
    )

    assert_equal "my-key-id", resolved_key_id
  end

  # -- #12: hmac-sha512 --

  def test_hmac_sha512
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: "test-shared-secret",
      key: shared_secret,
      algorithm: "hmac-sha512",
      components: %w[@method @authority]
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

  # -- #13: nonce round-trip --

  def test_nonce_roundtrip_in_verification
    nonce = "unique-nonce-value-12345"

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :get,
      headers: default_headers,
      key_id: "test-shared-secret",
      key: shared_secret,
      components: %w[@method],
      nonce:
    )

    assert_includes sig_headers["Signature-Input"], %(nonce="#{nonce}")

    headers = default_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url: default_url,
      method: :get,
      headers:,
      key: shared_secret
    )
  end

  def test_tag_roundtrip_in_verification
    tag = "web-bot-auth"

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :get,
      headers: default_headers,
      key_id: "test-shared-secret",
      key: shared_secret,
      components: %w[@method],
      tag:
    )

    assert_includes sig_headers["Signature-Input"], %(tag="#{tag}")

    headers = default_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url: default_url,
      method: :get,
      headers:,
      key: shared_secret
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

  def test_raises_on_unsupported_component
    error = assert_raises(HTTPSignature::UnsupportedComponent) do
      HTTPSignature.create(
        url: default_url,
        method: :get,
        headers: {},
        key: shared_secret,
        key_id: "test",
        components: %w[@method @unsupported-component]
      )
    end

    assert_equal "Unsupported component: @unsupported-component", error.message
  end

  def test_rejects_duplicate_components
    error = assert_raises(HTTPSignature::UnsupportedComponent) do
      HTTPSignature.create(
        url: default_url,
        method: :get,
        headers: default_headers,
        key: shared_secret,
        key_id: "test",
        components: %w[@method @authority @method]
      )
    end

    assert_equal "Duplicate component: @method", error.message
  end

  def test_rejects_signature_params_as_component
    error = assert_raises(HTTPSignature::UnsupportedComponent) do
      HTTPSignature.create(
        url: default_url,
        method: :get,
        headers: default_headers,
        key: shared_secret,
        key_id: "test",
        components: %w[@method @signature-params]
      )
    end

    assert_equal "@signature-params cannot be included as a component", error.message
  end

  def test_request_target_component
    url = "https://example.com/path?param=value"

    sig_headers = HTTPSignature.create(
      url:,
      method: :get,
      headers: default_headers,
      key_id: "test",
      key: shared_secret,
      components: %w[@method @request-target],
      created: 1
    )

    assert_includes sig_headers["Signature-Input"], '"@request-target"'

    headers = default_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url:,
      method: :get,
      headers:,
      key: shared_secret
    )
  end

  def test_request_target_component_without_query
    url = "https://example.com/path"

    sig_headers = HTTPSignature.create(
      url:,
      method: :get,
      headers: default_headers,
      key_id: "test",
      key: shared_secret,
      components: %w[@method @request-target],
      created: 1
    )

    headers = default_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url:,
      method: :get,
      headers:,
      key: shared_secret
    )
  end

  def test_query_param_component
    url = "https://example.com/path?foo=bar&baz=qux"

    sig_headers = HTTPSignature.create(
      url:,
      method: :get,
      headers: default_headers,
      key_id: "test",
      key: shared_secret,
      components: ["@method", "@query-param;name=\"foo\""],
      created: 1
    )

    assert_includes sig_headers["Signature-Input"], '"@query-param";name="foo"'

    headers = default_headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url:,
      method: :get,
      headers:,
      key: shared_secret
    )
  end

  def test_query_param_missing_raises
    url = "https://example.com/path?foo=bar"

    assert_raises(HTTPSignature::MissingComponent) do
      HTTPSignature.create(
        url:,
        method: :get,
        headers: default_headers,
        key_id: "test",
        key: shared_secret,
        components: ["@method", "@query-param;name=\"missing\""],
        created: 1
      )
    end
  end

  def test_empty_header_value
    url = "https://example.com/foo"
    headers = default_headers.merge("x-empty" => "")

    sig_headers = HTTPSignature.create(
      url:,
      method: :get,
      headers:,
      key_id: "test",
      key: shared_secret,
      components: %w[@method x-empty],
      created: 1
    )

    signed_headers = headers.merge(sig_headers)

    assert HTTPSignature.valid?(
      url:,
      method: :get,
      headers: signed_headers,
      key: shared_secret
    )
  end

  # -- Structured Field parameter tests (RFC 9421 Sections 2.1.2-2.1.3) --

  # -- Structured Field parameter tests (RFC 9421 Sections 2.1.2-2.1.4) --

  def test_content_digest_with_key_parameter
    url = "https://example.com/foo"
    body = '{"hello": "world"}'
    digest = Digest::SHA256.digest(body)
    headers = default_headers.merge(
      "content-digest" => "sha-256=:#{Base64.strict_encode64(digest)}:",
      "content-type" => "application/json"
    )

    sig_headers = HTTPSignature.create(
      url:,
      method: :post,
      headers:,
      body:,
      key_id: "test",
      key: shared_secret,
      components: ["@method", "content-digest;key=\"sha-256\""],
      created: 1
    )

    assert_includes sig_headers["Signature-Input"], "\"content-digest\";key=\"sha-256\""

    signed_headers = headers.merge(sig_headers)
    assert HTTPSignature.valid?(
      url:,
      method: :post,
      headers: signed_headers,
      body:,
      key: shared_secret
    )
  end

  def test_accept_with_sf_parameter
    url = "https://example.com/foo"
    headers = default_headers.merge("accept" => "text/html, application/json;q=0.9")

    sig_headers = HTTPSignature.create(
      url:,
      method: :get,
      headers:,
      key_id: "test",
      key: shared_secret,
      components: ["@method", "accept;sf"],
      created: 1
    )

    assert_includes sig_headers["Signature-Input"], "\"accept\";sf"

    signed_headers = headers.merge(sig_headers)
    assert HTTPSignature.valid?(
      url:,
      method: :get,
      headers: signed_headers,
      key: shared_secret
    )
  end

  def test_cache_control_with_key_parameter
    url = "https://example.com/foo"
    headers = default_headers.merge("cache-control" => "max-age=60, must-revalidate")

    sig_headers = HTTPSignature.create(
      url:,
      method: :get,
      headers:,
      key_id: "test",
      key: shared_secret,
      components: ["@method", "cache-control;key=\"max-age\""],
      created: 1
    )

    assert_includes sig_headers["Signature-Input"], "\"cache-control\";key=\"max-age\""

    signed_headers = headers.merge(sig_headers)
    assert HTTPSignature.valid?(
      url:,
      method: :get,
      headers: signed_headers,
      key: shared_secret
    )
  end

  def test_header_with_bs_parameter
    url = "https://example.com/foo"
    headers = default_headers.merge("x-custom" => "some-value")

    sig_headers = HTTPSignature.create(
      url:,
      method: :get,
      headers:,
      key_id: "test",
      key: shared_secret,
      components: ["@method", "x-custom;bs"],
      created: 1
    )

    assert_includes sig_headers["Signature-Input"], "\"x-custom\";bs"

    signed_headers = headers.merge(sig_headers)
    assert HTTPSignature.valid?(
      url:,
      method: :get,
      headers: signed_headers,
      key: shared_secret
    )
  end

  def test_req_parameter_for_response_signing
    url = "https://example.com/foo"
    request_headers = {"content-type" => "application/json"}
    response_headers = default_headers.merge("content-type" => "text/html")

    sig_headers = HTTPSignature.create(
      url:,
      method: :get,
      headers: response_headers,
      key_id: "test",
      key: shared_secret,
      components: ["@status", "content-type;req"],
      status: 200,
      created: 1,
      attached_request: {headers: request_headers}
    )

    assert_includes sig_headers["Signature-Input"], "\"content-type\";req"

    signed_headers = response_headers.merge(sig_headers)
    assert HTTPSignature.valid?(
      url:,
      method: :get,
      headers: signed_headers,
      key: shared_secret,
      status: 200,
      attached_request: {headers: request_headers}
    )
  end

  def test_req_parameter_without_attached_request_raises
    url = "https://example.com/foo"
    headers = default_headers.merge("content-type" => "application/json")

    assert_raises(HTTPSignature::MissingComponent) do
      HTTPSignature.create(
        url:,
        method: :get,
        headers:,
        key_id: "test",
        key: shared_secret,
        components: ["@status", "content-type;req"],
        status: 200,
        created: 1
      )
    end
  end

  def test_sf_and_bs_mutual_exclusion
    assert_raises(HTTPSignature::UnsupportedComponent) do
      HTTPSignature.create(
        url: "https://example.com/foo",
        method: :get,
        headers: default_headers.merge("x-test" => "value"),
        key_id: "test",
        key: shared_secret,
        components: ["@method", "x-test;sf;bs"],
        created: 1
      )
    end
  end

  def test_key_parameter_missing_member_raises
    url = "https://example.com/foo"
    headers = default_headers.merge("cache-control" => "max-age=60")

    assert_raises(HTTPSignature::MissingComponent) do
      HTTPSignature.create(
        url:,
        method: :get,
        headers:,
        key_id: "test",
        key: shared_secret,
        components: ["@method", "cache-control;key=\"no-such-key\""],
        created: 1
      )
    end
  end

  def test_create_returns_content_digest_when_body_present
    result = HTTPSignature.create(
      url: "https://example.com/webhook",
      method: :post,
      headers: {"Content-Type" => "application/json"},
      body: '{"id":1}',
      key: shared_secret,
      key_id: "test",
      created: 1
    )

    assert result.key?("Content-Digest"), "Expected Content-Digest in result"
    assert_match(/sha-256=:.*:/, result["Content-Digest"])
  end

  def test_create_does_not_return_content_digest_without_body
    result = HTTPSignature.create(
      url: "https://example.com/protected",
      method: :get,
      key: shared_secret,
      key_id: "test",
      created: 1
    )

    refute result.key?("Content-Digest"), "Expected no Content-Digest for bodyless request"
  end

  def test_create_does_not_return_content_digest_when_caller_provides_it
    digest = "sha-256=:#{Base64.strict_encode64(Digest::SHA256.digest('{"id":1}'))}:"
    result = HTTPSignature.create(
      url: "https://example.com/webhook",
      method: :post,
      headers: {"Content-Type" => "application/json", "Content-Digest" => digest},
      body: '{"id":1}',
      key: shared_secret,
      key_id: "test",
      created: 1
    )

    refute result.key?("Content-Digest"), "Expected no Content-Digest when caller already provides it"
  end

  def test_valid_auto_detects_label
    result = HTTPSignature.create(
      url: "https://example.com/resource",
      method: :get,
      key: shared_secret,
      key_id: "test-key-a",
      created: 1_618_884_473,
      label: "my-sig"
    )

    assert HTTPSignature.valid?(
      url: "https://example.com/resource",
      method: :get,
      headers: result,
      key: shared_secret
    )
  end

  def test_valid_auto_detects_first_label_with_multiple_signatures
    first = HTTPSignature.create(
      url: "https://example.com/resource",
      method: :get,
      key: shared_secret,
      key_id: "test-key-a",
      created: 1_618_884_473,
      label: "first-sig"
    )

    second = HTTPSignature.create(
      url: "https://example.com/resource",
      method: :get,
      key: shared_secret,
      key_id: "test-key-b",
      created: 1_618_884_473,
      label: "second-sig"
    )

    combined_headers = {
      "Signature-Input" => "#{first["Signature-Input"]}, #{second["Signature-Input"]}",
      "Signature" => "#{first["Signature"]}, #{second["Signature"]}"
    }

    # Auto-detect picks first label, which has key_id "test-key-a"
    resolved_key_ids = []
    resolver = ->(key_id) {
      resolved_key_ids << key_id
      shared_secret
    }

    HTTPSignature.valid?(
      url: "https://example.com/resource",
      method: :get,
      headers: combined_headers,
      key_resolver: resolver
    )
    assert_equal ["test-key-a"], resolved_key_ids

    # Explicit label picks second, which has key_id "test-key-b"
    resolved_key_ids.clear
    HTTPSignature.valid?(
      url: "https://example.com/resource",
      method: :get,
      headers: combined_headers,
      key_resolver: resolver,
      label: "second-sig"
    )
    assert_equal ["test-key-b"], resolved_key_ids
  end
end
