# frozen_string_literal: true

require "test_helper"
require "action_controller"
require "action_dispatch/testing/integration"
require "http_signature/rails"

class RailsSignatureController < ActionController::API
  include HTTPSignature::Rails::Controller

  before_action :verify_http_signature!

  def show
    head :ok
  end
end

class RailsLabeledSignatureController < ActionController::API
  include HTTPSignature::Rails::Controller

  before_action -> { verify_http_signature!(label: "sig2") }

  def show
    head :ok
  end
end

class RailsMaxAgeSignatureController < ActionController::API
  include HTTPSignature::Rails::Controller

  before_action -> { verify_http_signature!(max_age: 60) }

  def show
    head :ok
  end
end

class RailsIntegrationTest < ActionDispatch::IntegrationTest
  class TestApp
    def self.routes
      @routes ||= ActionDispatch::Routing::RouteSet.new.tap do |routes|
        routes.draw do
          get "/protected", to: RailsSignatureController.action(:show)
          get "/protected-label", to: RailsLabeledSignatureController.action(:show)
          get "/protected-max-age", to: RailsMaxAgeSignatureController.action(:show)
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
      config.keys = [{id: "key-1", value: "MySecureKey"}]
    end
  end

  test "allows requests with a valid signature" do
    date_header = "Tue, 20 Apr 2021 02:07:55 GMT"
    signed_headers = signed_request_headers(
      url: "http://test.host/protected",
      date_header:
    )

    assert HTTPSignature.valid?(
      url: "http://test.host/protected",
      method: :get,
      headers: {"date" => date_header, "host" => "test.host"}.merge(signed_headers),
      key: "MySecureKey"
    )

    perform_request(headers: {
      "Date" => date_header,
      "Host" => "test.host",
      "Signature-Input" => signed_headers["Signature-Input"],
      "Signature" => signed_headers["Signature"]
    })

    assert_response :success
  end

  test "allows selecting a specific signature label" do
    date_header = "Tue, 20 Apr 2021 02:07:55 GMT"
    valid_headers = signed_request_headers(
      url: "http://test.host/protected-label",
      date_header:,
      label: "sig2"
    )

    perform_request(
      path: "/protected-label",
      headers: {
        "Date" => date_header,
        "Host" => "test.host",
        "Signature-Input" => 'sig1=("@method");created=1;keyid="key-1", ' + valid_headers["Signature-Input"],
        "Signature" => "sig1=:invalid:, #{valid_headers["Signature"]}"
      }
    )

    assert_response :success
  end

  test "rejects signatures older than max_age" do
    date_header = "Tue, 20 Apr 2021 02:07:55 GMT"
    signed_headers = signed_request_headers(
      url: "http://test.host/protected-max-age",
      date_header:,
      created: Time.now.to_i - 120
    )

    perform_request(
      path: "/protected-max-age",
      headers: {
        "Date" => date_header,
        "Host" => "test.host",
        "Signature-Input" => signed_headers["Signature-Input"],
        "Signature" => signed_headers["Signature"]
      }
    )

    assert_response :unauthorized
    assert_equal "Invalid signature", @response.body
  end

  test "rejects requests missing signature headers" do
    perform_request

    assert_response :unauthorized
    assert_equal "No signature header", @response.body
  end

  test "rejects requests with an invalid signature" do
    perform_request(headers: {
      "Signature-Input" => 'sig1=("@method");created=1;keyid="key-1"',
      "Signature" => "sig1=:invalid:"
    })

    assert_response :unauthorized
    assert_equal "Invalid signature", @response.body
  end

  private

  def signed_request_headers(url:, date_header:, label: nil, created: nil)
    options = {
      url:,
      method: :get,
      headers: {"date" => date_header, "host" => "test.host"},
      key: "MySecureKey",
      key_id: "key-1"
    }
    options[:label] = label if label
    options[:created] = created if created
    HTTPSignature.create(**options)
  end

  def perform_request(path: "/protected", headers: {})
    get path, headers: headers
  end
end
