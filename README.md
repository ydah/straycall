<h1 align="center">Straycall</h1>

<p align="center">
  <strong>Report and block unintended syscalls in Ruby builds and tests</strong>
</p>

<p align="center">
  <a href="https://rubygems.org/gems/straycall"><img src="https://img.shields.io/gem/v/straycall.svg?colorB=38bdf8" alt="Gem Version"></a>
  <a href="https://rubygems.org/gems/straycall"><img src="https://img.shields.io/gem/dt/straycall.svg" alt="Downloads"></a>
  <img src="https://img.shields.io/badge/ruby-%3E%3D%203.1-ruby.svg" alt="Ruby Version">
  <a href="https://github.com/ydah/straycall/actions/workflows/main.yml"><img src="https://github.com/ydah/straycall/actions/workflows/main.yml/badge.svg" alt="Ruby CI"></a>
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
</p>

<p align="center">
  <a href="https://ydah.github.io/straycall/">Website</a> ·
  <a href="#features">Features</a> ·
  <a href="#installation">Installation</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#integrations">Integrations</a> ·
  <a href="#how-it-works">How It Works</a> ·
  <a href="#known-limitations">Limitations</a>
</p>

---

Straycall runs an unfiltered supervisor over Linux [seccomp user notifications](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html) to report and block unintended network, filesystem, and process access. Each report includes the responsible Ruby backtrace when available.

> [!WARNING]
> Straycall detects accidents; it is not a security boundary for hostile code. Pointer-based policy checks, symbolic links, existing file descriptors, and kernel interfaces outside seccomp's reach leave intentional escape routes.

On unsupported platforms, non-MRI Ruby, or with `STRAYCALL=0`, Straycall is a no-op and the wrapped command runs normally.

## Features

- Network policies for connections, Unix sockets, binds, and listeners
- Filesystem policies for writes and sensitive reads
- Process policies for allowed and denied executables
- Ruby backtraces with native-library fallback
- `fail`, `warn`, `record`, and interactive `prompt` modes
- CLI, YAML, and Ruby configuration
- RSpec and Minitest integrations
- Console and versioned JSON reports
- Automatic no-op behavior outside supported Linux environments

## Installation

Add Straycall to your Gemfile:

```ruby
gem "straycall"
```

Then install:

```sh
bundle install
```

### Requirements

- Linux x86_64 or aarch64
- Linux 5.5+ with seccomp user notifications and `CONTINUE`
- MRI Ruby 3.1+
- `seccomp-notify` 0.2.x

Container runtimes may block `seccomp(2)` in their own profile. Use an isolated container with `--security-opt seccomp=unconfined` when needed.

## Quick Start

The CLI keeps the supervisor outside the filtered command, so it does not interfere with the command's `Process.wait` calls.

Run a test suite with a YAML policy:

```sh
straycall --config .straycall.yml -- bundle exec rspec
```

Write a JSON report:

```sh
straycall --report-path tmp/straycall.json -- ruby script.rb
```

Record observed access as a reviewable policy:

```sh
straycall --record -- bundle exec rspec
```

Prompt while installing dependencies:

```sh
straycall --preset=bundle-install -- bundle install
```

### Violation Modes

| Mode | Behavior |
|------|----------|
| `fail` | Deny the syscall with `EPERM` and exit nonzero |
| `warn` | Allow the syscall and report it |
| `record` | Allow the syscall and write a reviewable policy |
| `prompt` | Ask through `/dev/tty`; deny when no TTY is available |

The default mode is `fail`.

Record mode writes `.straycall.recorded.yml` and refuses to replace an existing file. Review it before moving it to `.straycall.yml`; pass `--force` only when replacing a previous recording intentionally.

## Configuration

Create `.straycall.yml` in your project root:

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

| Option | Default | Description |
|--------|---------|-------------|
| `network.default` | `deny` | Allow or deny network endpoints not listed in `network.allow` |
| `write.default` | `allow` | Allow or deny writes outside `write.allow` |
| `exec.default` | `allow` | Allow or deny executables outside `exec.allow` |
| `on_violation` | `fail` | Select `fail`, `warn`, `record`, or `prompt` |
| `report_backtrace` | `true` | Include Ruby backtraces in reports |
| `report_path` | unset | Write a versioned JSON report to this path |

Hosts are resolved once while loading the configuration. Paths are expanded, but symbolic links are deliberately not resolved.

### Ruby Configuration

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

## Integrations

### RSpec and Minitest

Load the integration at the top of the test helper:

```ruby
# RSpec
require "straycall/rspec"

# Minitest
require "straycall/minitest"
```

In-process mode starts a clean detached supervisor with `Process.spawn`, associates violations with the current test, and checks the supervisor health pipe. Prefer the CLI if tests use broad `Process.wait` calls or fork heavily; filters are inherited and cannot be removed.

### Reports

Console reports include the syscall, target, current test, Ruby backtrace, native-library fallback, and an allow-list suggestion. Set `report_path` to write a versioned JSON document:

```json
{
  "version": 1,
  "violations": [
    {
      "syscall": "connect",
      "tid": 123,
      "target": {
        "type": "inet",
        "host": "192.0.2.1",
        "port": 443
      },
      "action": "denied"
    }
  ]
}
```

## How It Works

1. Straycall starts an unfiltered supervisor before the target command.
2. The target installs a seccomp filter for the configured syscall classes.
3. Linux pauses matching syscalls and sends user notifications to the supervisor.
4. The supervisor reads the target, evaluates the policy, and allows or denies the call.
5. Straycall joins violations with the current test and Ruby backtrace, then writes the configured reports.

## Known Limitations

1. Straycall is not a security boundary. Allowing a pointer-based syscall with `continue!` is subject to TOCTOU.
2. vDSO calls such as normal clock reads cannot be intercepted.
3. File descriptors opened before filter installation are outside the policy.
4. `io_uring_setup` is denied so io_uring cannot bypass monitored syscalls. `allow_io_uring!` opts out, but network and filesystem coverage is then incomplete.
5. Ruby backtraces require MRI 3.1+; native calls fall back to `/proc/<tid>/maps`.
6. Filesystem checks use the unresolved path string. A symlink can point outside an allowed root.
7. If the supervisor dies, the kernel returns `ENOSYS`; integrations detect the health-pipe closure as soon as they regain control.
8. A connected `sendto`, `sendmsg`, or `sendmmsg` without an explicit destination relies on the earlier monitored `connect`; Straycall cannot recover a peer address from the target file descriptor.
9. Listener tracking observes an allowed `bind` before the kernel returns. It prevents accidental auto-bind listeners, but it is not a hostile-code boundary.
10. In-process integrations only filter the thread that installs seccomp. Load them before starting application threads; Straycall warns when threads already exist.

## Development

```sh
bundle install
bundle exec rake
gem build straycall.gemspec
```

Real seccomp integration examples skip automatically outside supported Linux environments.

On Linux, `ruby benchmark/require_overhead.rb` checks that read-only `openat` overhead stays below 10% across 100,000 generated require files. Set `STRAYCALL_BENCHMARK_FILES` to scale the workload.

## Contributing

Bug reports and pull requests are welcome at https://github.com/ydah/straycall.

## License

Released under the [MIT License](LICENSE.txt).
