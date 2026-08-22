# Changelog

All notable changes to Straycall are documented here.

## v0.1.0 - 2026-08-22

- Add Linux seccomp-notify supervision for network, filesystem writes, sensitive reads, and process execution.
- Add Ruby backtrace reporting, native symbol fallback, console and JSON reports.
- Add CLI, YAML and Ruby configuration, record and prompt modes, and a bundle-install preset.
- Add RSpec and Minitest integrations with supervisor health checks.
- Add conditional `openat` filtering and unconnected `sendmsg` monitoring.
- Monitor explicit network binds and support connected destination-less UDP sends.
- Block auto-bound listeners, unsupported socket families, and batched datagram bypasses.
- Inspect the kernel-capped portion of oversized `sendmmsg` batches.
- Resolve `execveat` empty paths through their file descriptors and preserve signal exit codes.
- Preserve in-process suite failures when the reporter thread stops responding.
- Preserve in-process suite failures when writing the violation report fails.
- Return a failing CLI status for denied prompts and serialize concurrent prompts and console entries.
- Reject empty, non-string, and NUL-containing policy paths and hosts at configuration time.
- Synchronize only the latest test example so large clean suites cannot fill the reporter socket.
- Monitor legacy x86 `open` and `creat` entry points under filesystem policies.
- Calculate the performance gate from paired-run ratios to reduce host-load skew.
- Add automatic no-op behavior on unsupported platforms.
