# frozen_string_literal: true

require "straycall"
Straycall.config.report_path = ENV.fetch("STRAYCALL_TEST_REPORT")
require "straycall/rspec"
require "socket"

RSpec.describe "guarded" do
  it("connects") { TCPSocket.new("192.0.2.1", 443) rescue Errno::EPERM }
end
