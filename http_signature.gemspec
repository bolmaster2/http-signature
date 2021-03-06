lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'http_signature/version'

Gem::Specification.new do |spec|
  spec.name          = 'http_signature'
  spec.version       = HTTPSignature::VERSION
  spec.authors       = ['Joel Larsson']
  spec.email         = ['bolmaster2@gmail.com']

  spec.summary       = 'Create and validate HTTP request signature'
  spec.description   = 'Create and validate HTTP request signature according to draft: https://tools.ietf.org/html/draft-cavage-http-signatures-09'
  spec.homepage      = 'https://github.com/bolmaster2/http-signature'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'minitest'
  spec.add_development_dependency 'faraday'
end
