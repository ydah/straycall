# frozen_string_literal: true

require "straycall"
Straycall.config.report_path = ENV.fetch("STRAYCALL_TEST_REPORT")
Straycall.config.report_backtrace = false
require "straycall/rspec"
require "socket"
Straycall::Target.reporter.thread.kill.join if ENV["STRAYCALL_KILL_REPORTER"]

RSpec.describe "guarded" do
  it("connects") { TCPSocket.new("192.0.2.1", 443) rescue Errno::EPERM }
end
