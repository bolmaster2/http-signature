# HTTP signature gem

This is a Ruby gem implementing the [HTTP Message Signatures RFC 9421 standard](https://www.rfc-editor.org/rfc/rfc9421.txt). Always adhere to the standard

## Tests
- Run all tests: `bundle exec rake test`
- Run single test file: `bundle exec rake test TEST=test/http_signature_test.rb`
- Run single test: `bundle exec rake test TEST=test/http_signature_test.rb TESTOPTS="--name=/test_rsa_pss_sha512/"`
