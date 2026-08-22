# Straycall

Straycall reports and blocks unintended network, filesystem, and process access from Ruby builds and test suites. It runs an unfiltered supervisor over Linux `seccomp` user notifications and includes the responsible Ruby backtrace in its report.

> [!WARNING]
> Straycall detects accidents; it is not a security boundary for hostile code. Pointer-based policy checks, symbolic links, existing file descriptors, and kernel interfaces outside seccomp's reach leave intentional escape routes.

On macOS, Windows, non-MRI Ruby, an unsupported kernel, or with `STRAYCALL=0`, requiring and configuring Straycall is a no-op. The wrapped command runs normally.

## Requirements

- Linux x86_64 or aarch64 with seccomp user notifications and `CONTINUE` (Linux 5.5+)
- MRI Ruby 3.1+
- `seccomp-notify` 0.2.x

Container runtimes may block `seccomp(2)` in their own profile. Use an isolated container with `--security-opt seccomp=unconfined` when needed.

## Installation

```ruby
gem "straycall"
```

## CLI (recommended)

The CLI keeps the supervisor outside the filtered command, so it does not interfere with the command's `Process.wait` calls.

```sh
straycall --config .straycall.yml -- bundle exec rspec
straycall --report-path tmp/straycall.json -- ruby script.rb
straycall --record --policy-path .straycall.yml -- bundle exec rspec
straycall --preset=bundle-install -- bundle install
```

`--warn` and `--record` allow the syscall after reporting it. `--prompt` asks through `/dev/tty`; without a TTY it denies. The default `fail` mode and a denied prompt return `EPERM` and make the CLI exit nonzero.

## YAML policy

```yaml
network:
  default: deny
  allow:
    - host: 127.0.0.1
      ports: [5432, 6379]
    - unix: /var/run/postgresql/.s.PGSQL.5432
write:
  default: deny
  allow: [tmp, log, coverage, /tmp]
  deny_read: [/etc/shadow, ~/.ssh, ~/.aws, ~/.gem/credentials]
exec:
  default: allow
  deny: [/usr/bin/curl, /usr/bin/wget]
on_violation: fail
report_backtrace: true
report_path: tmp/straycall.json
```

Hosts are resolved once while loading the configuration. Paths are expanded but symbolic links are deliberately not resolved.

## Ruby configuration

```ruby
require "straycall"

Straycall.configure do |config|
  config.deny_network!
  config.allow_loopback ports: [5432, 6379]
  config.allow_host "registry.internal.example", ports: [443]
  config.allow_unix "/var/run/postgresql/.s.PGSQL.5432"

  config.allow_write_under "tmp", "log", "coverage", Dir.tmpdir
  config.deny_write_elsewhere!
  config.deny_read "/etc/shadow", "~/.ssh"

  config.allow_exec "/usr/bin/git", "/usr/bin/make"
  config.deny_exec_elsewhere!
  # config.allow_io_uring! # disables complete syscall coverage
  config.report_path = "tmp/straycall.json"
end
```

## RSpec and Minitest

Load the integration at the top of the test helper:

```ruby
# RSpec
require "straycall/rspec"

# Minitest
require "straycall/minitest"
```

This in-process mode starts a clean detached supervisor with `Process.spawn`, associates violations with the current test, and checks the supervisor health pipe. Prefer the CLI if tests use broad `Process.wait` calls or fork heavily; filters are inherited and cannot be removed.

## Reports

Console output includes the syscall, target, current test, Ruby backtrace (MRI), a `/proc/<tid>/maps` native-library fallback, and an allow-list suggestion. `report_path` writes a versioned JSON document:

```json
{"version":1,"violations":[{"syscall":"connect","tid":123,"target":{"type":"inet","host":"192.0.2.1","port":443},"action":"denied"}]}
```

## Known limitations

1. This is not a security boundary. Allowing a pointer-based syscall with `continue!` is subject to TOCTOU.
2. vDSO calls such as normal clock reads cannot be intercepted.
3. File descriptors opened before filter installation are outside the policy.
4. `io_uring_setup` is denied so io_uring cannot bypass monitored syscalls. `allow_io_uring!` opts out, but network and filesystem coverage is then incomplete.
5. Ruby backtraces require MRI 3.1+; native calls fall back to `/proc/<tid>/maps`.
6. Filesystem checks use the unresolved path string. A symlink can point outside an allowed root.
7. If the supervisor dies, the kernel returns `ENOSYS`; integrations detect the health-pipe closure as soon as they regain control.
8. A connected `sendto`/`sendmsg`/`sendmmsg` without an explicit destination relies on the earlier monitored `connect`; Straycall cannot recover a peer address from the target file descriptor.
9. Listener tracking observes an allowed `bind` before the kernel returns. It prevents accidental auto-bind listeners, but it is not a hostile-code boundary.

## Development

```sh
ruby -Ilib -S rspec
gem build straycall.gemspec
```

Real seccomp integration examples skip automatically outside supported Linux environments.

On Linux, `ruby benchmark/require_overhead.rb` checks that read-only `openat` overhead stays below 10% across 100,000 generated require files, using the median ratio of five alternating pairs after warmup. Set `STRAYCALL_BENCHMARK_FILES` to scale the workload.
