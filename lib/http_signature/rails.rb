# frozen_string_literal: true

require 'http_signature'
require 'action_controller'

module HTTPSignature
  module Rails
    module Controller
      extend ActiveSupport::Concern

      private

      # Use as a Rails before_action to enforce HTTP Message Signatures on an action.
      def verify_http_signature!
        request_headers = normalized_request_headers
        signature_input_header = request_headers['signature-input']
        signature_header = request_headers['signature']

        return render status: :unauthorized, plain: 'No signature header' unless signature_input_header && signature_header

        request_body = read_request_body

        valid_signature = HTTPSignature.valid?(
          url: request.url,
          method: request.request_method,
          headers: request_headers,
          body: request_body || '',
          key_resolver: ->(key_id) { HTTPSignature.key(key_id) }
        )

        return if valid_signature

        render status: :unauthorized, plain: 'Invalid signature'
      rescue HTTPSignature::SignatureError, ArgumentError
        render status: :unauthorized, plain: 'Invalid signature'
      end

      def normalized_request_headers
        headers = {}

        request.each_header do |key, value|
          next unless key.start_with?('HTTP_')
          next if key == 'HTTP_VERSION'

          canonical_key = key.sub('HTTP_', '').tr('_', '-').downcase
          headers[canonical_key] = value
        end

        %w[CONTENT_TYPE CONTENT_LENGTH].each do |env_key|
          next unless (value = request.get_header(env_key))

          headers[env_key.downcase.tr('_', '-')] = value
        end

        headers
      end

      def read_request_body
        return '' unless request.body

        body_content = request.body.read
        request.body.rewind if request.body.respond_to?(:rewind)
        body_content
      end
    end
  end
end

