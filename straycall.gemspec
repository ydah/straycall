# frozen_string_literal: true

require_relative "lib/straycall/version"

Gem::Specification.new do |spec|
  spec.name = "straycall"
  spec.version = Straycall::VERSION
  spec.authors = ["Yudai Takada"]
  spec.email = ["t.yudai92@gmail.com"]

  spec.summary = "Report and block unintended syscalls in Ruby builds and tests"
  spec.description = "A Linux seccomp-notify sandbox that reports network, filesystem, and process violations."
  spec.homepage = "https://rubygems.org/gems/straycall"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"
  spec.metadata["rubygems_mfa_required"] = "true"
  spec.metadata["homepage_uri"] = spec.homepage

  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .gitignore .rspec spec/ .github/])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "seccomp-notify", "~> 0.3"
end
