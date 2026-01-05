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
      valid_signature = HTTPSignature.valid?(
        url: request.url,
        method: request.request_method,
        headers: request_headers,
        body: request_body || "",
        key_resolver: ->(key_id) { HTTPSignature.key(key_id) }
      )
    rescue HTTPSignature::SignatureError
      return [401, {}, ["Invalid signature"]]
    end

    return [401, {}, ["Invalid signature"]] unless valid_signature

    @app.call(env)
  end

  private

  def parse_request_headers(request)
    request_headers = {}

    request.each_header do |header|
      if header[0].include?("HTTP_") && header[0] != "HTTP_VERSION"
        request_headers[header[0].gsub("HTTP_", "").tr("_", "-").downcase] = header[1]
      end
    end

    request_headers
  end

  def path_excluded?(path)
    self.class.exclude_paths.any? do |exclude_path|
      !!path.match(exclude_path)
    end
  end
end
