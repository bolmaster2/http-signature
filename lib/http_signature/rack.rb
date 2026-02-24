# frozen_string_literal: true

require "http_signature"
require "rack"

# Rack middleware using http-signature gem to validate signature on every incoming request
class HTTPSignature::Rack
  class << self
    attr_accessor :exclude_paths
  end

  def initialize(app)
    @app = app
    self.class.exclude_paths ||= []
  end

  def call(env)
    request = ::Rack::Request.new(env)

    return @app.call(env) if path_excluded?(request.path)

    request_headers = parse_request_headers(request)
    signature_input_header = request_headers["signature-input"]
    signature_header = request_headers["signature"]
    return [401, {}, ["No signature header"]] unless signature_input_header && signature_header

    begin
      request_body =
        if request.body
          body_content = request.body.read
          request.body.rewind if request.body.respond_to?(:rewind)
          body_content
        else
          ""
        end
      HTTPSignature.valid?(
        url: request.url,
        method: request.request_method,
        headers: request_headers,
        body: request_body || "",
        key_resolver: ->(key_id) { HTTPSignature.key(key_id) }
      )
    rescue HTTPSignature::SignatureError
      return [401, {}, ["Invalid signature"]]
    end

    @app.call(env)
  end

  private

  def parse_request_headers(request)
    request_headers = {}

    request.each_header do |key, value|
      if key.start_with?("HTTP_") && key != "HTTP_VERSION"
        request_headers[key.sub("HTTP_", "").tr("_", "-").downcase] = value
      end
    end

    %w[CONTENT_TYPE CONTENT_LENGTH].each do |env_key|
      value = request.get_header(env_key)
      request_headers[env_key.downcase.tr("_", "-")] = value if value
    end

    request_headers
  end

  def path_excluded?(path)
    self.class.exclude_paths.any? do |exclude_path|
      !!path.match(exclude_path)
    end
  end
end
