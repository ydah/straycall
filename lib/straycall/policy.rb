# frozen_string_literal: true

module Straycall
  module Policy
    FORBIDDEN_NOTIFY = %i[read write ppoll poll select futex clock_nanosleep rt_sigreturn sendmsg].freeze

    module_function

    def seccomp(_config)
      notified = %i[socket connect sendto]
      validate_notified!(*notified)

      Seccomp::Notify::Policy.new do
        notify(*notified)
        deny :ptrace
      end
    end

    def validate_notified!(*names)
      invalid = names.map(&:to_sym) & FORBIDDEN_NOTIFY
      raise ConfigurationError, "cannot notify reporter syscall(s): #{invalid.join(", ")}" unless invalid.empty?

      true
    end
  end
end
