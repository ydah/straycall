# frozen_string_literal: true

require "minitest/autorun"
require "straycall"
Straycall.config.report_path = ENV.fetch("STRAYCALL_TEST_REPORT")
require "straycall/minitest"
require "socket"

class GuardedMinitest < Minitest::Test
  def test_connects
    TCPSocket.new("192.0.2.1", 443)
  rescue Errno::EPERM
    nil
  end
end
