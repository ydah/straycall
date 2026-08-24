# Changelog

All notable changes to Straycall are documented here.

## v0.3.0 - 2026-08-24

- Reuse CLI supervision from RSpec and Minitest integrations and prevent descendant Ruby processes from consuming another process's reporter messages.
- Keep listener-transfer descriptors reserved and warn when in-process installation cannot cover existing threads.
- Cover additional filesystem mutation syscalls, writable shared mappings, listeners, and local netlink sockets.
- Make recorded policies non-destructive, exact, and replayable for raw socket families and unbound listeners.
- Resolve executable aliases and support directory-scoped executable allow rules.
- Reduce notification and report-writing overhead, handle IPv4-mapped loopback addresses, and warn when supervision is unavailable.
- Require seccomp-notify 0.3 for thread-safe termination, x32 rejection, and listener-transfer hardening.

## v0.1.0 - 2026-08-23

- Initial release.
