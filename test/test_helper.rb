# frozen_string_literal: true

if ENV["COVERAGE"]
  require "simplecov"
  SimpleCov.start do
    add_filter "/test/"
    minimum_coverage 85
  end
end

require "minitest/autorun"
require_relative "../lib/http_signature"
