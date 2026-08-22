# frozen_string_literal: true

module Straycall
  module Handlers
    module Exec
      def handle_exec(request, dirfd_index, path_index)
        path_address = request.args[path_index]
        path = dirfd_index && request.read(path_address, 1) == "\0" ? "" : request.read_string(path_address)
        dirfd = dirfd_index ? request.args[dirfd_index] : Policy::Filesystem::AT_FDCWD
        path = @config.filesystem.resolve(path, tid: request.tid, dirfd:)
        target = {type: "exec", path:}
        if !@config.exec.allowed?(path) || @config.on_violation == :record
          record_violation(request, target, %(allow_exec #{path.inspect}))
        else
          request.continue!(unsafe: true)
        end
      rescue PathResolutionError, Seccomp::Notify::MemoryReadError
        record_violation(request, {type: "exec", path: "?"}, nil)
      end
    end
  end
end
