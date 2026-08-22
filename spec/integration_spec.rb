# frozen_string_literal: true

require "rbconfig"
require "tmpdir"
require "open3"
require "straycall/supervisor"

RSpec.describe "Linux supervision" do
  before do
    skip "seccomp user notifications are unavailable" unless Straycall.available?
  end

  it "denies connect and writes a report" do
    Dir.mktmpdir do |directory|
      config = Straycall::Config.new
      config.report_path = File.join(directory, "report.json")
      status, violations = Straycall::Supervisor.new(config).run(
        [RbConfig.ruby, "-rsocket", "-e", 'TCPSocket.new("192.0.2.1", 443)']
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
        [RbConfig.ruby, "-e", 'File.write("/tmp/straycall-forbidden", "x")']
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
      [RbConfig.ruby, "-e", 'exit(system("/usr/bin/true") ? 0 : 1)']
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

    _status, violations = Straycall::Supervisor.new(config).run([RbConfig.ruby, "-e", script])

    expect(violations.count { |item| item.syscall == :connect }).to eq(100)
  end

  it "fails an RSpec suite and associates its example" do
    Dir.mktmpdir do |directory|
      report = File.join(directory, "report.json")
      suite = File.join(directory, "guarded_spec.rb")
      File.write(suite, <<~RUBY)
        require "straycall"
        Straycall.config.report_path = #{report.inspect}
        require "straycall/rspec"
        require "socket"
        RSpec.describe("guarded") do
          it("connects") { TCPSocket.new("192.0.2.1", 443) rescue Errno::EPERM }
        end
      RUBY

      _stdout, _stderr, status = Open3.capture3(
        RbConfig.ruby, "-I#{File.expand_path("../lib", __dir__)}", "-S", "rspec", suite
      )

      expect(status).not_to be_success
      expect(::JSON.parse(File.read(report)).dig("violations", 0, "example", "description")).to include("connects")
    end
  end
end
