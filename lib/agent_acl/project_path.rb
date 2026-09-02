# frozen_string_literal: true

module AgentAcl
  # Validates that managed paths remain inside the project without symlink escapes.
  module ProjectPath
    module_function

    # @return [String] validated absolute path
    # @raise [AgentAcl::Error] if the path escapes the project or traverses a symlink
    def validate!(root, path)
      root = File.realpath(root)
      expanded = File.expand_path(path)
      relative = relative_path(root, expanded)
      reject_symlinks(root, relative)
      expanded
    end

    def relative_path(root, expanded)
      prefix = "#{root}#{File::SEPARATOR}"
      fail Error, "managed path must stay inside the project: #{expanded}" unless expanded.start_with?(prefix)

      expanded.delete_prefix(prefix)
    end
    private_class_method :relative_path

    def reject_symlinks(root, relative)
      relative.split(File::SEPARATOR).reduce(root) do |parent, component|
        candidate = File.join(parent, component)
        fail Error, "managed path contains a symlink: #{relative}" if File.symlink?(candidate)

        candidate
      end
    end
    private_class_method :reject_symlinks
  end
end
