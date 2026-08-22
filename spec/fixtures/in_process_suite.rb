# frozen_string_literal: true

require "straycall"
Straycall.config.report_path = ENV.fetch("STRAYCALL_TEST_REPORT")
Straycall.config.report_backtrace = false
require "straycall/rspec"
require "socket"
Straycall::Target.reporter.thread.kill.join if ENV["STRAYCALL_KILL_REPORTER"]
if ENV["STRAYCALL_KILL_SUPERVISOR"]
  children = File.read("/proc/#{Process.pid}/task/#{Process.pid}/children").split.map!(&:to_i)
  Process.kill("KILL", children.fetch(0))
  sleep(0.01) until Seccomp::Notify.supervisor_alive? == false
end

RSpec.describe "guarded" do
  it("connects") { TCPSocket.new("192.0.2.1", 443) rescue Errno::EPERM }
end
