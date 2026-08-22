# frozen_string_literal: true

require "straycall/reporter/client"
require "straycall/reporter/thread_reporter"
require "straycall/reporter/symbolizer"

RSpec.describe Straycall::Reporter do
  it "returns another Ruby thread's backtrace" do
    supervisor_socket, target_socket = UNIXSocket.pair
    reporter = Straycall::Reporter::ThreadReporter.new(target_socket).start
    ready = Queue.new
    blocker = Queue.new
    worker = Thread.new { ready << true; blocker.pop }
    ready.pop

    trace = Straycall::Reporter::Client.new(supervisor_socket).backtrace(worker.native_thread_id)

    expect(trace).to include(a_string_including("reporter_spec.rb"))
  ensure
    blocker&.push(true)
    worker&.join
    reporter&.stop
    supervisor_socket&.close unless supervisor_socket&.closed?
  end

  it "times out when the reporter does not answer" do
    supervisor_socket, target_socket = UNIXSocket.pair
    client = Straycall::Reporter::Client.new(supervisor_socket, timeout: 0.01)

    expect(client.backtrace(Thread.current.native_thread_id)).to be_nil
  ensure
    supervisor_socket&.close unless supervisor_socket&.closed?
    target_socket&.close unless target_socket&.closed?
  end

  it "stops waiting after the reporter dies" do
    supervisor_socket, target_socket = UNIXSocket.pair
    reporter = Straycall::Reporter::ThreadReporter.new(target_socket).start
    reporter.thread.kill.join
    client = Straycall::Reporter::Client.new(supervisor_socket, timeout: 0.1)

    expect(client.backtrace(Thread.current.native_thread_id)).to be_nil
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    expect(client.backtrace(Thread.current.native_thread_id)).to be_nil
    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 0.05
  ensure
    supervisor_socket&.close unless supervisor_socket&.closed?
  end

  it "serializes concurrent backtrace requests" do
    supervisor_socket, target_socket = UNIXSocket.pair
    reporter = Straycall::Reporter::ThreadReporter.new(target_socket).start
    client = Straycall::Reporter::Client.new(supervisor_socket)
    ready = Queue.new
    blocker = Queue.new
    workers = Array.new(100) { Thread.new { ready << true; blocker.pop } }
    100.times { ready.pop }

    traces = workers.map { |worker| Thread.new { client.backtrace(worker.native_thread_id) } }.each(&:join).map(&:value)

    expect(traces).to all(be_an(Array))
  ensure
    workers&.length&.times { blocker.push(true) }
    workers&.each(&:join)
    reporter&.stop
    supervisor_socket&.close unless supervisor_socket&.closed?
  end

  it "acknowledges violations in the target" do
    supervisor_socket, target_socket = UNIXSocket.pair
    reporter = Straycall::Reporter::ThreadReporter.new(target_socket).start
    client = Straycall::Reporter::Client.new(supervisor_socket)

    client.notify_violation

    expect(reporter.violation?).to be(true)
  ensure
    reporter&.stop
    supervisor_socket&.close unless supervisor_socket&.closed?
  end

  it "symbolizes an instruction pointer from proc maps" do
    maps = "7f000000-7f001000 r-xp 00001000 00:00 0 /tmp/foo_ext.so\n"

    expect(Straycall::Reporter::Symbolizer.call(1, 0x7f000f20, maps:)).to eq("/tmp/foo_ext.so+0x1f20")
  end
end
