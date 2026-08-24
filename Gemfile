# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in straycall.gemspec
gemspec

local_seccomp_notify = File.expand_path("../seccomp-notify", __dir__)
if File.directory?(local_seccomp_notify)
  gem "seccomp-notify", path: local_seccomp_notify
else
  gem "seccomp-notify", github: "ydah/seccomp-notify", ref: "1d4d30d67723b8cfadd068545f4e59c73dbc97bb"
end

gem "rake", "~> 13.0"
gem "benchmark"

gem "rspec", "~> 3.0"
gem "minitest", "~> 5.0"
