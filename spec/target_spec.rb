# frozen_string_literal: true

require "fcntl"
require "straycall/target"

RSpec.describe Straycall::Target do
  it "does not attach an inherited reporter in a descendant process" do
    socket, inherited_socket = UNIXSocket.pair
    inherited_socket.close_on_exec = false
    ENV["STRAYCALL_REPORT_FD"] = inherited_socket.fileno.to_s
    ENV["STRAYCALL_REPORT_PID"] = (Process.pid + 1).to_s

    described_class.start_from_environment

    expect(described_class.reporter).to be_nil
    expect { inherited_socket.fcntl(Fcntl::F_GETFD) }.to raise_error(Errno::EBADF)
  ensure
    socket&.close
    inherited_socket&.close rescue nil
    ENV.delete("STRAYCALL_REPORT_FD")
    ENV.delete("STRAYCALL_REPORT_PID")
  end
end
