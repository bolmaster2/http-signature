# frozen_string_literal: true

require 'test_helper'
require 'action_controller'
require 'action_dispatch/testing/integration'
require 'http_signature/rails'

class RailsSignatureController < ActionController::API
  include HTTPSignature::Rails::Controller

  before_action :verify_http_signature!

  def show
    head :ok
  end
end

class RailsIntegrationTest < ActionDispatch::IntegrationTest
  class TestApp
    def self.routes
      @routes ||= ActionDispatch::Routing::RouteSet.new.tap do |routes|
        routes.draw do
          get '/protected', to: RailsSignatureController.action(:show)
        end
      end
    end

    def self.call(env)
      routes.call(env)
    end
  end

  def app
    TestApp
  end

  setup do
    HTTPSignature.configure do |config|
      config.keys = [{ id: 'key-1', value: 'MySecureKey' }]
    end
  end

  test 'allows requests with a valid signature' do
    date_header = 'Tue, 20 Apr 2021 02:07:55 GMT'
    signed_headers = HTTPSignature.create(
      url: 'http://test.host/protected',
      method: :get,
      headers: { 'date' => date_header, 'host' => 'test.host' },
      key: 'MySecureKey',
      key_id: 'key-1'
    )

    assert HTTPSignature.valid?(
      url: 'http://test.host/protected',
      method: :get,
      headers: { 'date' => date_header, 'host' => 'test.host' }.merge(signed_headers),
      key: 'MySecureKey'
    )

    perform_request({
      'Date' => date_header,
      'Host' => 'test.host',
      'Signature-Input' => signed_headers['Signature-Input'],
      'Signature' => signed_headers['Signature']
    })

    assert_response :success
  end

  test 'rejects requests missing signature headers' do
    perform_request

    assert_response :unauthorized
    assert_equal 'No signature header', @response.body
  end

  test 'rejects requests with an invalid signature' do
    perform_request({
      'Signature-Input' => 'sig1=("@method");created=1;keyid="key-1"',
      'Signature' => 'sig1=:invalid:'
    })

    assert_response :unauthorized
    assert_equal 'Invalid signature', @response.body
  end

  private

  def perform_request(headers = {})
    get '/protected', headers: headers
  end
end

