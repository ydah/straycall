# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in straycall.gemspec
gemspec

local_seccomp_notify = File.expand_path("../seccomp-notify", __dir__)
if File.directory?(local_seccomp_notify)
  gem "seccomp-notify", path: local_seccomp_notify
else
  gem "seccomp-notify", github: "ydah/seccomp-notify", ref: "7da1274ec5d1116a54c3d94e9ff788318625eef3"
end

gem "rake", "~> 13.0"
gem "benchmark"

gem "rspec", "~> 3.0"
gem "minitest", "~> 5.0"
