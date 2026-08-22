# frozen_string_literal: true

require "fcntl"

module Straycall
  module Policy
    class Filesystem
      AT_FDCWD = -100
      WRITE_FLAGS = Fcntl::O_WRONLY | Fcntl::O_RDWR | Fcntl::O_CREAT | Fcntl::O_TRUNC | Fcntl::O_APPEND

      def initialize(cache_size: 4096)
        raise ArgumentError, "cache_size must be positive" unless cache_size.is_a?(Integer) && cache_size.positive?

        @write_default = :allow
        @write_roots = []
        @read_denials = []
        @cache_size = cache_size
        @cache = {}
        @mutex = Mutex.new
      end

      def allow_write_under(path)
        @write_roots << normalize_config_path(path)
        clear_cache
      end

      def deny_write_elsewhere!
        @write_default = :deny
        clear_cache
      end

      def deny_read(path)
        @read_denials << normalize_config_path(path)
        clear_cache
      end

      def active?
        @write_default == :deny || !@read_denials.empty?
      end

      def read_denials?
        !@read_denials.empty?
      end

      def write?(flags)
        (flags & WRITE_FLAGS).positive?
      end

      def allowed_write?(path)
        cached([:write, path]) do
          @write_default == :allow || path.match?(%r{\A/proc/(?:self|\d+)/task/\d+/comm\z}) || @write_roots.any? { |root| under?(path, root) }
        end
      end

      def denied_read?(path)
        cached([:read, path]) { @read_denials.any? { |root| under?(path, root) } }
      end

      def resolve(path, tid:, dirfd: AT_FDCWD)
        return File.expand_path(path) if path.start_with?(File::SEPARATOR)

        base = if signed(dirfd) == AT_FDCWD
          File.readlink("/proc/#{tid}/cwd")
        else
          File.readlink("/proc/#{tid}/fd/#{signed(dirfd)}")
        end
        File.expand_path(path, base)
      rescue Errno::ENOENT, Errno::EACCES => error
        raise PathResolutionError, "cannot resolve target path through /proc: #{error.message}"
      end

      def marshal_dump
        [@write_default, @write_roots, @read_denials, @cache_size]
      end

      def marshal_load(values)
        @write_default, @write_roots, @read_denials, @cache_size = values
        @cache = {}
        @mutex = Mutex.new
      end

      private

      def normalize_config_path(path)
        File.expand_path(path.to_s)
      end

      def signed(value)
        value >= (1 << 63) ? value - (1 << 64) : value
      end

      def under?(path, root)
        path == root || path.start_with?("#{root}#{File::SEPARATOR}")
      end

      def cached(key)
        @mutex.synchronize do
          return @cache[key] if @cache.key?(key)

          @cache[key] = yield
          @cache.shift if @cache.length > @cache_size
          @cache[key]
        end
      end

      def clear_cache
        @mutex.synchronize { @cache.clear }
      end
    end
  end
end
