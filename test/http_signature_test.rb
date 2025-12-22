# frozen_string_literal: true

require 'minitest/autorun'
require './lib/http_signature'

class HTTPSignatureTest < Minitest::Test
  # RFC 9421 Appendix B.1.5 - Example Shared Secret
  def test_shared_secret
    Base64.decode64('uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==')
  end

  # RFC 9421 Appendix B.1.2 - Example RSA-PSS Key
  def rsa_pss_private_key
    OpenSSL::PKey.read(<<~PEM)
      -----BEGIN PRIVATE KEY-----
      MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv
      P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5
      3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr
      FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA
      AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw
      9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy
      c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq
      pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X
      aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4
      XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ
      HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD
      2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N
      RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx
      DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6
      vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm
      rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi
      4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL
      FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/
      OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx
      NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR
      NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ
      3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE
      t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND
      dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF
      S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR
      rOjr9w349JooGXhOxbu8nOxX
      -----END PRIVATE KEY-----
    PEM
  end

  def rsa_pss_public_key
    OpenSSL::PKey.read(<<~PEM)
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
      +QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
      oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
      gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
      Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
      aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
      2wIDAQAB
      -----END PUBLIC KEY-----
    PEM
  end

  # RFC 9421 Appendix B.1.1 - Example RSA Key (for rsa-v1_5-sha256)
  def rsa_private_key
    OpenSSL::PKey::RSA.new(<<~PEM)
      -----BEGIN RSA PRIVATE KEY-----
      MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP
      BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd
      JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75
      jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI
      lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ
      SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56
      vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE
      CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW
      +m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA
      yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR
      Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J
      YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM
      cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw
      DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1
      mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT
      qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67
      B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv
      9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn
      f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo
      81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa
      /2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG
      IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m
      qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P
      WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ
      EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=
      -----END RSA PRIVATE KEY-----
    PEM
  end

  def rsa_public_key
    OpenSSL::PKey::RSA.new(<<~PEM)
      -----BEGIN RSA PUBLIC KEY-----
      MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
      WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
      MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
      kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
      uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
      PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
      -----END RSA PUBLIC KEY-----
    PEM
  end

  # RFC 9421 Appendix B.1.3 - Example ECC P-256 Test Key
  def ecc_p256_private_key
    OpenSSL::PKey::EC.new(<<~PEM)
      -----BEGIN EC PRIVATE KEY-----
      MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
      AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
      4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
      -----END EC PRIVATE KEY-----
    PEM
  end

  def ecc_p256_public_key
    OpenSSL::PKey.read(<<~PEM)
      -----BEGIN PUBLIC KEY-----
      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
      w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
      -----END PUBLIC KEY-----
    PEM
  end

  # RFC 9421 Appendix B.1.4 - Example Ed25519 Test Key
  def ed25519_private_key
    OpenSSL::PKey.read(<<~PEM)
      -----BEGIN PRIVATE KEY-----
      MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
      -----END PRIVATE KEY-----
    PEM
  end

  def ed25519_public_key
    OpenSSL::PKey.read(<<~PEM)
      -----BEGIN PUBLIC KEY-----
      MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
      -----END PUBLIC KEY-----
    PEM
  end

  # Generate P-384 key for testing (not in RFC examples, but needed for ecdsa-p384-sha384)
  def ecc_p384_private_key
    @ecc_p384_private_key ||= OpenSSL::PKey::EC.generate('secp384r1')
  end

  def ecc_p384_public_key
    ecc_p384_private_key
  end

  # Standard test request from RFC 9421 Appendix B.2
  def default_url
    'https://example.com/foo?param=Value&Pet=dog'
  end

  def default_headers
    { 'date' => 'Tue, 20 Apr 2021 02:07:55 GMT' }
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
      key_id: 'test-shared-secret',
      key: test_shared_secret,
      algorithm: 'hmac-sha256',
      covered_components: %w[@method @authority @target-uri date],
      created: 1_618_884_473
    )

    assert sig_headers['Signature-Input']
    assert sig_headers['Signature']

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers: default_headers,
      key: test_shared_secret,
      signature_input_header: sig_headers['Signature-Input'],
      signature_header: sig_headers['Signature']
    )
  end

  # RFC 9421 Section 3.3.1 - RSASSA-PSS Using SHA-512
  def test_rsa_pss_sha512
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      body: default_body,
      key_id: 'test-key-rsa-pss',
      key: rsa_pss_private_key,
      algorithm: 'rsa-pss-sha512',
      covered_components: %w[@method @authority @path],
      created: 1_618_884_473
    )

    assert sig_headers['Signature-Input']
    assert sig_headers['Signature']

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers: default_headers,
      body: default_body,
      key: rsa_pss_public_key,
      signature_input_header: sig_headers['Signature-Input'],
      signature_header: sig_headers['Signature']
    )
  end

  # RFC 9421 Section 3.3.2 - RSASSA-PKCS1-v1_5 Using SHA-256
  def test_rsa_v1_5_sha256
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: 'test-key-rsa',
      key: rsa_private_key,
      algorithm: 'rsa-v1_5-sha256',
      covered_components: %w[@method @authority @path],
      created: 1_618_884_480
    )

    assert sig_headers['Signature-Input']
    assert sig_headers['Signature']

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers: default_headers,
      key: rsa_public_key,
      signature_input_header: sig_headers['Signature-Input'],
      signature_header: sig_headers['Signature']
    )
  end

  # RFC 9421 Section 3.3.4 - ECDSA Using Curve P-256 DSS and SHA-256
  def test_ecdsa_p256_sha256
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: 'test-key-ecc-p256',
      key: ecc_p256_private_key,
      algorithm: 'ecdsa-p256-sha256',
      covered_components: %w[@method @authority @path],
      created: 1_618_884_473
    )

    assert sig_headers['Signature-Input']
    assert sig_headers['Signature']

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers: default_headers,
      key: ecc_p256_public_key,
      signature_input_header: sig_headers['Signature-Input'],
      signature_header: sig_headers['Signature']
    )
  end

  # RFC 9421 Section 3.3.5 - ECDSA Using Curve P-384 DSS and SHA-384
  def test_ecdsa_p384_sha384
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: 'test-key-ecc-p384',
      key: ecc_p384_private_key,
      algorithm: 'ecdsa-p384-sha384',
      covered_components: %w[@method @authority @path],
      created: 1_618_884_473
    )

    assert sig_headers['Signature-Input']
    assert sig_headers['Signature']

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers: default_headers,
      key: ecc_p384_public_key,
      signature_input_header: sig_headers['Signature-Input'],
      signature_header: sig_headers['Signature']
    )
  end

  # RFC 9421 Section 3.3.6 - EdDSA Using Curve edwards25519
  def test_ed25519
    headers = {
      'date' => 'Tue, 20 Apr 2021 02:07:55 GMT',
      'content-type' => 'application/json',
      'content-length' => '18'
    }

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers:,
      key_id: 'test-key-ed25519',
      key: ed25519_private_key,
      algorithm: 'ed25519',
      covered_components: %w[date @method @path @authority content-type content-length],
      created: 1_618_884_473
    )

    assert sig_headers['Signature-Input']
    assert sig_headers['Signature']

    assert HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers:,
      key: ed25519_public_key,
      signature_input_header: sig_headers['Signature-Input'],
      signature_header: sig_headers['Signature']
    )
  end

  def test_adds_content_digest_when_body_present
    body = '{"hello":"world"}'
    headers = {}
    url = 'https://example.com/submit'

    sig_headers = HTTPSignature.create(
      url:,
      method: :post,
      headers:,
      body:,
      key_id: 'test',
      key: test_shared_secret
    )

    assert_includes sig_headers['Signature-Input'], 'content-digest'
  end

  def test_raises_when_required_header_missing
    assert_raises(HTTPSignature::MissingComponent) do
      HTTPSignature.create(
        url: 'https://example.com/test',
        method: :get,
        headers: {},
        key: test_shared_secret,
        covered_components: %w[date]
      )
    end
  end

  def test_rejects_tampered_signature_hmac
    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: 'test-shared-secret',
      key: test_shared_secret,
      algorithm: 'hmac-sha256',
      covered_components: %w[@method @authority]
    )

    refute HTTPSignature.valid?(
      url: default_url,
      method: :get, # Changed from :post
      headers: default_headers,
      key: test_shared_secret,
      signature_input_header: sig_headers['Signature-Input'],
      signature_header: sig_headers['Signature']
    )
  end

  def test_rejects_wrong_key_ecdsa_p256
    other_key = OpenSSL::PKey::EC.generate('prime256v1')

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: 'test-key-ecc-p256',
      key: ecc_p256_private_key,
      algorithm: 'ecdsa-p256-sha256',
      covered_components: %w[@method @authority]
    )

    refute HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers: default_headers,
      key: other_key,
      signature_input_header: sig_headers['Signature-Input'],
      signature_header: sig_headers['Signature']
    )
  end

  def test_rejects_wrong_key_ed25519
    other_key = OpenSSL::PKey.generate_key('ED25519')

    sig_headers = HTTPSignature.create(
      url: default_url,
      method: :post,
      headers: default_headers,
      key_id: 'test-key-ed25519',
      key: ed25519_private_key,
      algorithm: 'ed25519',
      covered_components: %w[@method @authority]
    )

    refute HTTPSignature.valid?(
      url: default_url,
      method: :post,
      headers: default_headers,
      key: other_key,
      signature_input_header: sig_headers['Signature-Input'],
      signature_header: sig_headers['Signature']
    )
  end

  def test_raises_on_unsupported_algorithm
    assert_raises(HTTPSignature::UnsupportedAlgorithm) do
      HTTPSignature.create(
        url: default_url,
        method: :get,
        headers: {},
        key: 'key',
        algorithm: 'unknown-algorithm'
      )
    end
  end
end
