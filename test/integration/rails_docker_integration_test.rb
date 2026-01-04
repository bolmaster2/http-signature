# frozen_string_literal: true

require "./test/test_helper"
require "net/http"
require "timeout"

class RailsDockerIntegrationTest < Minitest::Test
  IMAGE = "http-signature-rails"
  CONTAINER = "http-signature-rails-test"
  PORT = 3000

  def setup
    skip "docker not available" unless system("command -v docker >/dev/null")
    skip "node not available" unless system("command -v node >/dev/null")
    skip "npm not available" unless system("command -v npm >/dev/null")

    system!("docker build -t #{IMAGE} -f test/integration/rails/Dockerfile .")
    system!("docker run -d --rm --name #{CONTAINER} -p #{PORT}:3000 #{IMAGE}")
    wait_for_server
    system!("npm install --prefix test/integration/rails")
  end

  def teardown
    system("docker stop #{CONTAINER} >/dev/null 2>&1")
  end

  def test_signed_and_unsigned_requests
    system!("node test/integration/rails/client.js http://localhost:#{PORT}")
  end

  private

  def wait_for_server
    uri = URI("http://localhost:#{PORT}/")
    Timeout.timeout(60) do
      loop do
        begin
          res = Net::HTTP.get_response(uri)
          break if res.is_a?(Net::HTTPSuccess) || res.is_a?(Net::HTTPRedirection)
        rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, EOFError
          # keep retrying
        end
        sleep 1
      end
    end
  end

  def system!(cmd)
    success = system(cmd)
    raise "Command failed: #{cmd}" unless success
  end
end
