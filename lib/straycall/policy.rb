# frozen_string_literal: true

module Straycall
  module Policy
    FORBIDDEN_NOTIFY = %i[read write ppoll poll select futex clock_nanosleep rt_sigreturn sendmsg].freeze

    module_function

    FILESYSTEM_NOTIFY = %i[openat openat2 unlinkat renameat renameat2 mkdirat].freeze
    LEGACY_FILESYSTEM_NOTIFY = %i[unlink rename mkdir].freeze
    EXEC_NOTIFY = %i[execve execveat].freeze

    def seccomp(config)
      notified = notification_names(config)
      validate_notified!(*notified)

      Seccomp::Notify::Policy.new do
        notify(*notified)
        deny :ptrace
      end
    end

    def notification_names(config)
      names = %i[socket connect sendto]
      # ponytail: seccomp-notify 0.1 has no scalar-argument filter; use notify_if upstream before enabling filesystem guards by default.
      if config.filesystem.active? || config.on_violation == :record
        names.concat(FILESYSTEM_NOTIFY)
        names.concat(LEGACY_FILESYSTEM_NOTIFY) if RUBY_PLATFORM.include?("linux") && RUBY_PLATFORM.include?("x86_64")
      end
      names.concat(EXEC_NOTIFY) if config.exec.active? || config.on_violation == :record
      names
    end

    def validate_notified!(*names)
      invalid = names.map(&:to_sym) & FORBIDDEN_NOTIFY
      raise ConfigurationError, "cannot notify reporter syscall(s): #{invalid.join(", ")}" unless invalid.empty?

      true
    end
  end
end
