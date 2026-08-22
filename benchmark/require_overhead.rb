# frozen_string_literal: true

require "benchmark"
require "rbconfig"
require "tmpdir"

abort "straycall is unavailable" unless RUBY_PLATFORM.include?("linux")

Dir.mktmpdir do |directory|
  files = File.join(directory, "files")
  Dir.mkdir(files)
  count = Integer(ENV.fetch("STRAYCALL_BENCHMARK_FILES", "100000"))
  source = <<~RUBY
    # frozen_string_literal: true

    module StraycallRequireBenchmark
      def self.loaded?
        true
      end

      def self.call(value)
        value
      end
    end
  RUBY
  count.times { |index| File.write(File.join(files, "f#{index}.rb"), source) }
  script = "Dir[#{files.inspect} + '/*.rb'].each { |file| require file }"
  config = File.join(directory, "config.yml")
  File.write(config, <<~YAML)
    network: {default: deny}
    write:
      default: deny
      allow: [#{directory}]
  YAML

  clean_environment = ENV.keys.grep(/\A(?:BUNDLE|BUNDLER|RUBY(?:OPT|LIB))/).to_h { |name| [name, nil] }
  plain_command = [RbConfig.ruby, "-e", script]
  guarded_command = [
    RbConfig.ruby,
    "-I#{File.expand_path("../lib", __dir__)}",
    "-I#{File.expand_path("../../seccomp-notify/lib", __dir__)}",
    File.expand_path("../exe/straycall", __dir__),
    "--config", config, "--", RbConfig.ruby, "-e", script
  ]
  measure = lambda do |command|
    Benchmark.realtime { system(clean_environment, *command, out: File::NULL, exception: true) }
  end

  measure.call(plain_command)
  measure.call(guarded_command)
  samples = {plain_command => [], guarded_command => []}
  5.times do |index|
    first, second = index.even? ? [plain_command, guarded_command] : [guarded_command, plain_command]
    samples.fetch(first) << measure.call(first)
    samples.fetch(second) << measure.call(second)
  end
  plain = samples.fetch(plain_command).sort.fetch(2)
  guarded = samples.fetch(guarded_command).sort.fetch(2)
  overhead = ((guarded / plain) - 1) * 100
  puts format("files=%d plain=%.3fs guarded=%.3fs overhead=%.1f%%", count, plain, guarded, overhead)
  abort "overhead exceeded 10%" if overhead > 10
end
