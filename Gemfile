# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in straycall.gemspec
gemspec

local_seccomp_notify = File.expand_path("../seccomp-notify", __dir__)
gem "seccomp-notify", path: local_seccomp_notify if File.directory?(local_seccomp_notify)

gem "rake", "~> 13.0"

gem "rspec", "~> 3.0"
gem "minitest", "~> 5.0"
