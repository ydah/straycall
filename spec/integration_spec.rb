# frozen_string_literal: true

require "rbconfig"
require "tmpdir"
require "open3"
require "straycall/supervisor"
require "timeout"

RSpec.describe "Linux supervision" do
  let(:clean_ruby_env) do
    ENV.keys.grep(/\A(?:BUNDLE|BUNDLER|RUBY(?:OPT|LIB))/).to_h { |name| [name, nil] }
  end

  before do
    skip "seccomp user notifications are unavailable" unless Straycall.available?
  end

  it "denies connect and writes a report" do
    Dir.mktmpdir do |directory|
      config = Straycall::Config.new
      config.report_path = File.join(directory, "report.json")
      status, violations = Straycall::Supervisor.new(config).run(
        [clean_ruby_env, RbConfig.ruby, "-rsocket", "-e", 'TCPSocket.new("192.0.2.1", 443)']
      )

      expect(status).not_to be_success
      expect(violations.first.target).to eq(type: "inet", host: "192.0.2.1", port: 443)
      expect(::JSON.parse(File.read(config.report_path)).dig("violations", 0, "backtrace").join)
        .to include("-e:1")
    end
  end

  it "denies writes outside configured roots" do
    Dir.mktmpdir do |directory|
      config = Straycall::Config.new
      config.allow_write_under(directory)
      config.deny_write_elsewhere!
      status, violations = Straycall::Supervisor.new(config).run(
        [clean_ruby_env, RbConfig.ruby, "-e", 'File.write("/tmp/straycall-forbidden", "x")']
      )

      expect(status).not_to be_success
      expect(violations.map(&:syscall)).to include(:openat)
      expect(violations.map { |item| item.target[:path] }).to include("/tmp/straycall-forbidden")
    end
  end

  it "denies unlisted executables" do
    config = Straycall::Config.new
    config.allow_exec(RbConfig.ruby)
    config.deny_exec_elsewhere!
    _status, violations = Straycall::Supervisor.new(config).run(
      [clean_ruby_env, RbConfig.ruby, "-e", 'exit(system("/usr/bin/true") ? 0 : 1)']
    )

    expect(violations.map { |item| item.target[:path] }).to include("/usr/bin/true")
  end

  it "answers concurrent connect notifications without deadlocking" do
    config = Straycall::Config.new
    script = <<~RUBY
      require "socket"
      100.times.map do
        Thread.new { TCPSocket.new("192.0.2.1", 443) rescue Errno::EPERM }
      end.each(&:join)
    RUBY

    _status, violations = Straycall::Supervisor.new(config).run([clean_ruby_env, RbConfig.ruby, "-e", script])

    expect(violations.count { |item| item.syscall == :connect }).to eq(100)
  end

  it "denies an unconnected sendmsg destination" do
    config = Straycall::Config.new
    script = <<~RUBY
      require "socket"
      socket = UDPSocket.new
      socket.sendmsg("x", 0, Socket.sockaddr_in(53, "192.0.2.1"))
    RUBY

    _status, violations = Straycall::Supervisor.new(config).run([clean_ruby_env, RbConfig.ruby, "-e", script])

    expect(violations.map(&:syscall)).to include(:sendmsg)
    expect(violations.find { |item| item.syscall == :sendmsg }.target).to include(host: "192.0.2.1", port: 53)
  end

  it "allows connected UDP sends after the destination was approved" do
    config = Straycall::Config.new
    config.allow_loopback
    script = <<~RUBY
      require "socket"
      socket = UDPSocket.new
      socket.connect("127.0.0.1", 49152)
      socket.send("x", 0)
    RUBY

    status, violations = Straycall::Supervisor.new(config).run([clean_ruby_env, RbConfig.ruby, "-e", script])

    expect(status).to be_success
    expect(violations).to be_empty
  end

  it "denies binding an external listener under the default network policy" do
    config = Straycall::Config.new
    script = 'require "socket"; UDPSocket.new.bind("0.0.0.0", 0)'

    status, violations = Straycall::Supervisor.new(config).run([clean_ruby_env, RbConfig.ruby, "-e", script])

    expect(status).not_to be_success
    expect(violations.map(&:syscall)).to include(:bind)
  end

  it "does not notify read-only openat calls under a write policy" do
    config = Straycall::Config.new
    config.deny_write_elsewhere!

    status, violations = Straycall::Supervisor.new(config).run(
      [clean_ruby_env, RbConfig.ruby, "-e", 'File.read("/etc/hosts")']
    )

    expect(status).to be_success
    expect(violations).to be_empty
  end

  it "fails an RSpec suite and associates its example" do
    Dir.mktmpdir do |directory|
      report = File.join(directory, "report.json")
      output = File.join(directory, "subprocess.log")
      fixture = File.expand_path("fixtures/in_process_suite.rb", __dir__)
      environment = {"STRAYCALL_TEST_REPORT" => report}
      status = run_suite(environment, output, RbConfig.ruby, "-I#{File.expand_path("../lib", __dir__)}",
                         Gem.bin_path("rspec-core", "rspec"), fixture)

      expect(status).not_to be_success
      expect(File).to exist(report), File.read(output)
      violation = ::JSON.parse(File.read(report)).dig("violations", 0)
      expect(violation.dig("example", "description")).to include("connects")
      expect(violation).not_to have_key("backtrace")
    end
  end

  it "fails a Minitest suite and associates its test" do
    Dir.mktmpdir do |directory|
      report = File.join(directory, "report.json")
      output = File.join(directory, "subprocess.log")
      fixture = File.expand_path("fixtures/in_process_minitest.rb", __dir__)
      environment = {"STRAYCALL_TEST_REPORT" => report}
      status = run_suite(environment, output, RbConfig.ruby, "-I#{File.expand_path("../lib", __dir__)}", fixture)

      expect(status).not_to be_success
      expect(File).to exist(report), File.read(output)
      expect(::JSON.parse(File.read(report)).dig("violations", 0, "example", "description")).to include("test_connects")
    end
  end

  def run_suite(environment, output, *command)
    pid = Process.spawn(environment, *command, out: output, err: output)
    Timeout.timeout(10) { Process.waitpid2(pid).last }
  rescue Timeout::Error
    raise "subprocess timed out:\n#{File.read(output)}"
  ensure
    if pid
      Process.kill("KILL", pid) rescue nil
      Process.waitpid(pid) rescue nil
    end
  end
end
