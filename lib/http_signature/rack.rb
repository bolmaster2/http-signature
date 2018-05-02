# frozen_string_literal: true

require 'http_signature'

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
    request = Rack::Request.new(env)

    return @app.call(env) if path_excluded?(request.path)

    return [401, {}, ['No signature header']] unless request.get_header("HTTP_SIGNATURE")

    begin
      request_body = request.body.read
      request_headers = parse_request_headers(request)
      parsed_signature = parse_signature(request_headers)
      key = HTTPSignature.key(parsed_signature['keyId'])
    rescue
      return [401, {}, ['Invalid signature :(']]
    end

    headers_to_sign = request_headers.select { |k, v| parsed_signature['headers'].include?(k) }

    params = {
      url: request.path,
      method: request.request_method,
      headers: headers_to_sign,
      key: key,
      key_id: parsed_signature['keyId'],
      algorithm: parsed_signature['algorithm'],
      body: request_body ? request_body : '',
      query_string_params: Rack::Utils.parse_nested_query(request.query_string)
    }

    valid_signature =
      if parsed_signature['algorithm'].include?('rsa')
        HTTPSignature.valid?(**params)
      else
        HTTPSignature.create(**params) == request_headers['signature']
      end

    if valid_signature
      @app.call(env)
    else
      [401, {}, ['Invalid signature :(']]
    end
  end

  private

  def parse_request_headers(request)
    request_headers = {}

    request.each_header do |header|
      if header[0].include?('HTTP_') && header[0] != 'HTTP_VERSION'
        request_headers[header[0].gsub('HTTP_', '').gsub("_", "-").downcase] = header[1]
      end
    end

    request_headers
  end

  def parse_signature(request_headers)
    Rack::Utils.parse_nested_query(
      request_headers['signature'].gsub(',', '&')
    ).map do |k, v|
      [k, v.tr('"', '')]
    end.to_h
  end

  def path_excluded?(path)
    matches = self.class.exclude_paths.map do |exclude_path|
      path.match(exclude_path).present?
    end

    matches.select { |v| v == true }.length.positive?
  end
end
