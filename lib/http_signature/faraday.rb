# frozen_string_literal: true

require "http_signature"
require "faraday"

class HTTPSignature::Faraday < Faraday::Middleware
  class << self
    attr_accessor :key, :key_id
  end

  def initialize(app, options = nil)
    super(app)
    @options = options || {}
  end

  def call(env)
    options = merged_options(env)
    key = options.fetch(:key, self.class.key)
    key_id = options.fetch(:key_id, self.class.key_id)
    raise "key and key_id needs to be set" if key.nil? || key_id.nil?

    body =
      if env[:body]&.respond_to?(:read)
        string = env[:body].read
        env[:body].rewind
        string
      else
        env[:body].to_s
      end

    signature_headers = HTTPSignature.create(**signature_options(env:, key:, key_id:, body:, options:))

    signature_headers.each do |header, value|
      env[:request_headers][header] = value
    end

    @app.call(env)
  end

  private

  def merged_options(env)
    request_options = env.request.context&.dig(:http_signature) || {}
    @options.merge(request_options)
  end

  def signature_options(env:, key:, key_id:, body:, options:)
    {
      url: env[:url],
      method: env[:method],
      headers: env[:request_headers],
      key:,
      key_id:,
      body:,
      **create_options(options)
    }.tap do |signature_options|
      signature_options[:components] = options[:components] if options.key?(:components)
    end
  end

  def create_options(options)
    options.slice(:created, :expires, :nonce, :label, :include_alg, :algorithm)
  end
end
