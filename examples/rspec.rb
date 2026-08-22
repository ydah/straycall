# frozen_string_literal: true

require "tmpdir"
require "straycall"

Straycall.configure do |config|
  config.allow_loopback ports: [5432]
  config.allow_write_under "tmp", "log", "coverage", Dir.tmpdir
  config.deny_write_elsewhere!
  config.report_path = "tmp/straycall.json"
end

require "straycall/rspec"
