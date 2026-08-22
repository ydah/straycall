# frozen_string_literal: true

module Straycall
  module Handlers
    module Filesystem
      def handle_openat(request)
        handle_open(request, request.args[0], request.args[1], request.args[2])
      end

      def handle_openat2(request)
        flags = request.read(request.args[2], 8).unpack1("Q<")
        handle_open(request, request.args[0], request.args[1], flags)
      end

      def handle_path_mutation(request, dirfd, path_address)
        path = resolve_path(request, dirfd, path_address)
        target = {type: "file", path:, operation: request.syscall.to_s}
        if !@config.filesystem.allowed_write?(path) || @config.on_violation == :record
          record_violation(request, target, %(allow_write_under #{File.dirname(path).inspect}))
        else
          request.continue!(unsafe: true)
        end
      rescue Seccomp::Notify::MemoryReadError
        record_violation(request, {type: "file", path: "?"}, nil)
      end

      def handle_rename(request, source_dirfd, source_address, destination_dirfd, destination_address)
        source = resolve_path(request, source_dirfd, source_address)
        destination = resolve_path(request, destination_dirfd, destination_address)
        target = {type: "file", path: destination, source:, operation: request.syscall.to_s}
        allowed = @config.filesystem.allowed_write?(source) && @config.filesystem.allowed_write?(destination)
        if !allowed || @config.on_violation == :record
          record_violation(request, target, %(allow_write_under #{File.dirname(destination).inspect}))
        else
          request.continue!(unsafe: true)
        end
      rescue Seccomp::Notify::MemoryReadError
        record_violation(request, {type: "file", path: "?"}, nil)
      end

      private

      def handle_open(request, dirfd, path_address, flags)
        path = resolve_path(request, dirfd, path_address)
        filesystem = @config.filesystem
        write = filesystem.write?(flags)
        denied = write ? !filesystem.allowed_write?(path) : filesystem.denied_read?(path)
        target = {type: "file", path:, flags:}
        if denied || (@config.on_violation == :record && write)
          suggestion = write ? %(allow_write_under #{File.dirname(path).inspect}) : nil
          record_violation(request, target, suggestion)
        else
          request.continue!(unsafe: true)
        end
      rescue Seccomp::Notify::MemoryReadError
        record_violation(request, {type: "file", path: "?", flags:}, nil)
      end

      def resolve_path(request, dirfd, address)
        path = request.read_string(address)
        @config.filesystem.resolve(path, tid: request.tid, dirfd:)
      end
    end
  end
end
