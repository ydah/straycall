# frozen_string_literal: true

module Straycall
  module Policy
    module_function

    NETWORK_NOTIFY = %i[socket connect bind listen sendto sendmsg sendmmsg].freeze
    FILESYSTEM_NOTIFY = %i[
      openat openat2 unlinkat renameat renameat2 mkdirat linkat symlinkat
      truncate ftruncate fchmod fchmodat fchmodat2 fchown fchownat utimensat copy_file_range mmap
    ].freeze
    LEGACY_FILESYSTEM_NOTIFY = %i[
      open creat unlink rename mkdir rmdir link symlink chmod chown lchown
    ].freeze
    EXEC_NOTIFY = %i[execve execveat].freeze

    def seccomp(config)
      notified = notification_names(config)

      conditional = []
      conditional << :openat if notified.include?(:openat) && !config.filesystem.read_denials?
      conditional << :open if notified.include?(:open) && !config.filesystem.read_denials?
      conditional << :mmap if notified.include?(:mmap)
      Seccomp::Notify::Policy.new(deny_io_uring: !config.io_uring_allowed?) do
        notify(*(notified - conditional))
        notify_if(:openat, argument: 2, mask: Policy::Filesystem::WRITE_FLAGS) if conditional.include?(:openat)
        notify_if(:open, argument: 1, mask: Policy::Filesystem::WRITE_FLAGS) if conditional.include?(:open)
        notify_if(:mmap, argument: 3, mask: 1) if conditional.include?(:mmap)
        deny :ptrace
      end
    end

    def notification_names(config)
      names = config.network.allow_all? && config.on_violation != :record ? [] : NETWORK_NOTIFY.dup
      if config.filesystem.active? || config.on_violation == :record
        names.concat(FILESYSTEM_NOTIFY)
        names.concat(LEGACY_FILESYSTEM_NOTIFY) if RUBY_PLATFORM.include?("linux") && RUBY_PLATFORM.include?("x86_64")
      end
      names.concat(EXEC_NOTIFY) if config.exec.active? || config.on_violation == :record
      names
    end

  end
end
