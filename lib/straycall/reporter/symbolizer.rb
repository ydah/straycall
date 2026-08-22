# frozen_string_literal: true

module Straycall
  module Reporter
    module Symbolizer
      module_function

      def call(tid, instruction_pointer, maps: nil)
        lines = maps ? maps.each_line : File.foreach("/proc/#{Integer(tid)}/maps")
        lines.each do |line|
          range, _permissions, file_offset, _device, _inode, path = line.split(nil, 6)
          start_address, end_address = range.split("-", 2).map { |value| Integer(value, 16) }
          next unless (start_address...end_address).cover?(instruction_pointer)

          return unless path

          offset = instruction_pointer - start_address + Integer(file_offset, 16)
          return "#{path.strip}+0x#{offset.to_s(16)}"
        end
        nil
      rescue ArgumentError, Errno::ENOENT, Errno::EACCES
        nil
      end
    end
  end
end
