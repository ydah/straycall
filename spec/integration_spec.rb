# frozen_string_literal: true

require "rbconfig"
require "tmpdir"
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
end
