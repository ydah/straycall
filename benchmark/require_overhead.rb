# frozen_string_literal: true

require "benchmark"
require "rbconfig"
require "tmpdir"

abort "straycall is unavailable" unless RUBY_PLATFORM.include?("linux")

Dir.mktmpdir do |directory|
  files = File.join(directory, "files")
  Dir.mkdir(files)
  1_000.times { |index| File.write(File.join(files, "f#{index}.rb"), "# frozen_string_literal: true\n") }
  script = "Dir[#{files.inspect} + '/*.rb'].each { |file| require file }"
  config = File.join(directory, "config.yml")
  File.write(config, <<~YAML)
    network: {default: deny}
    write:
      default: deny
      allow: [#{directory}]
  YAML

  plain = Benchmark.realtime { system(RbConfig.ruby, "-e", script, out: File::NULL, exception: true) }
  guarded = Benchmark.realtime do
    system(
      RbConfig.ruby, "-I#{File.expand_path("../lib", __dir__)}", File.expand_path("../exe/straycall", __dir__),
      "--config", config, "--", RbConfig.ruby, "-e", script, out: File::NULL, exception: true
    )
  end
  puts format("plain=%.3fs guarded=%.3fs overhead=%.1f%%", plain, guarded, ((guarded / plain) - 1) * 100)
end
