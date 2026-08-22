# Changelog

All notable changes to Straycall are documented here.

## v0.1.0 - 2026-08-22

- Add Linux seccomp-notify supervision for network, filesystem writes, sensitive reads, and process execution.
- Add Ruby backtrace reporting, native symbol fallback, console and JSON reports.
- Add CLI, YAML and Ruby configuration, record and prompt modes, and a bundle-install preset.
- Add RSpec and Minitest integrations with supervisor health checks.
- Add conditional `openat` filtering and unconnected `sendmsg` monitoring.
- Monitor explicit network binds and support connected destination-less UDP sends.
- Add automatic no-op behavior on unsupported platforms.
