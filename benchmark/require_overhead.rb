# frozen_string_literal: true

require "benchmark"
require "rbconfig"
require "tmpdir"

abort "straycall is unavailable" unless RUBY_PLATFORM.include?("linux")

Dir.mktmpdir do |directory|
  files = File.join(directory, "files")
  Dir.mkdir(files)
  count = Integer(ENV.fetch("STRAYCALL_BENCHMARK_FILES", "100000"))
  count.times { |index| File.write(File.join(files, "f#{index}.rb"), "# frozen_string_literal: true\n") }
  script = "Dir[#{files.inspect} + '/*.rb'].each { |file| require file }"
  config = File.join(directory, "config.yml")
  File.write(config, <<~YAML)
    network: {default: deny}
    write:
      default: deny
      allow: [#{directory}]
  YAML

  clean_environment = ENV.keys.grep(/\A(?:BUNDLE|BUNDLER|RUBY(?:OPT|LIB))/).to_h { |name| [name, nil] }
  plain = Benchmark.realtime do
    system(clean_environment, RbConfig.ruby, "-e", script, out: File::NULL, exception: true)
  end
  guarded = Benchmark.realtime do
    system(
      clean_environment, RbConfig.ruby,
      "-I#{File.expand_path("../lib", __dir__)}",
      "-I#{File.expand_path("../../seccomp-notify/lib", __dir__)}",
      File.expand_path("../exe/straycall", __dir__),
      "--config", config, "--", RbConfig.ruby, "-e", script, out: File::NULL, exception: true
    )
  end
  overhead = ((guarded / plain) - 1) * 100
  puts format("files=%d plain=%.3fs guarded=%.3fs overhead=%.1f%%", count, plain, guarded, overhead)
  abort "overhead exceeded 10%" if overhead > 10
end
