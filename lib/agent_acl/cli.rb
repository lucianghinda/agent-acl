# frozen_string_literal: true

module AgentAcl
  # Dispatches the agent-acl command-line interface from a project root.
  class CLI
    USAGE = "Usage: agent-acl block edit <path>... | allow edit <path>... | list | version"
    UNSUPPORTED_RULE_CHARACTERS = /[\t\r\n*?\[\]{}()\\]/

    MANAGED_PATHS = %w[
      .agent-acl
      .agent-acl.d
      .agent-acl.d/guard.rb
      .agent-acl.d/installers.json
      .claude
      .claude/settings.json
      .codex
      .codex/hooks.json
      .opencode
      .opencode/plugin
      .opencode/plugin/agent-acl.js
      opencode.json
    ].freeze

    # @param root [String] project root used for paths and generated configuration
    # @param out [IO] normal command output
    # @param err [IO] warnings and errors
    def initialize(root: Dir.pwd, out: $stdout, err: $stderr, os_guard_factory: nil, installer_factories: nil)
      @root = File.realpath(root)
      @out = out
      @err = err
      @os_guard_factory = os_guard_factory || ->(path:) { OsGuard.new(path:) }
      @installer_factories = installer_factories
    end

    # Runs one CLI command.
    # @param argv [Array<String>] command-line arguments
    # @return [Integer] process exit status
    def run(argv)
      case argv
      in ["list"]
        list
      in ["version"]
        out.puts(VERSION)
        0
      in ["block", "edit", *paths] if paths.any?
        block(paths)
      in ["allow", "edit", *paths] if paths.any?
        allow(paths)
      else
        err.puts(USAGE)
        1
      end
    rescue StandardError => e
      err.puts("agent-acl: #{e.message}")
      1
    end

    private

    attr_reader :root, :out, :err, :os_guard_factory, :installer_factories

    def list
      Manifest.load(root, err:).entries.each { out.puts("edit blocked -> #{_1.path}") }
      0
    end

    def block(paths)
      targets = paths.map { validate_block_target(_1) }
      manifest = Manifest.load(root, err:)
      targets.each { protect_target(manifest, _1) }

      finish(manifest, :install)
    end

    def allow(paths)
      manifest = Manifest.load(root, err:)
      changed = false
      paths.each { |path| changed = allow_target(manifest, path) || changed }

      changed ? finish(manifest, :sync) : 0
    end

    def protect_target(manifest, path)
      already_protected = manifest.protected?(path)
      mode = recorded_mode(manifest, path) || file_mode(path)
      result = os_guard_factory.call(path:).protect
      persist_block(manifest, path, mode, already_protected)
      result.warnings.each { err.puts("agent-acl: warning: #{_1}") }
      report_block(path, already_protected)
    end

    def persist_block(manifest, path, mode, already_protected)
      manifest.add(path, mode:)
      manifest.write
    rescue StandardError
      os_guard_factory.call(path:).unprotect(mode:) unless already_protected
      raise
    end

    def report_block(path, already_protected)
      prefix = already_protected ? "already protected, re-applied:" : "protected"
      out.puts("#{prefix} #{relative_path(path)}")
    end

    def recorded_mode(manifest, path)
      manifest.entries.find { manifest.absolute_path(_1.path) == path }&.mode
    end

    # rubocop:disable Naming/PredicateMethod -- this mutates state and returns whether the path was changed
    def allow_target(manifest, given_path)
      path = File.expand_path(given_path, root)
      entry = manifest.entries.find { manifest.absolute_path(_1.path) == path }
      unless entry
        out.puts("not protected: #{relative_path(path)}")
        return false
      end

      os_guard_factory.call(path:).unprotect(mode: entry.mode)
      manifest.remove(path)
      manifest.write
      out.puts("allowed edits to #{entry.path}")
      true
    end
    # rubocop:enable Naming/PredicateMethod

    def finish(manifest, action)
      successful = apply_installers(manifest, action)
      restore_project_ownership
      successful ? 0 : 1
    end

    def validate_block_target(given_path)
      path = File.expand_path(given_path, root)
      fail Error, "#{given_path}: must be inside the project" unless inside_root?(path)
      fail Error, "#{given_path}: symlink targets cannot be protected" if File.symlink?(path)
      fail Error, "#{given_path}: not found" unless File.exist?(path)

      path = File.realpath(path)
      fail Error, "#{given_path}: must be inside the project" unless inside_root?(path)
      if relative_path(path).match?(UNSUPPORTED_RULE_CHARACTERS)
        fail Error, "#{given_path}: path contains unsupported characters for agent rules"
      end
      fail Error, "#{given_path}: directory targets cannot be protected" if File.directory?(path)
      fail Error, "#{given_path}: must be a regular file" unless File.file?(path)

      path
    end

    def inside_root?(path)
      path.start_with?("#{root}#{File::SEPARATOR}")
    end

    def file_mode(path)
      File.stat(path).mode & 0o7777
    end

    def relative_path(path)
      return path unless inside_root?(path)

      path.delete_prefix("#{root}#{File::SEPARATOR}")
    end

    def apply_installers(manifest, action)
      factories = installer_factories || default_installer_factories
      successful = true

      factories.each do |factory|
        factory.call(root:, manifest:).public_send(action)
      rescue StandardError => e
        err.puts("agent-acl: agent configuration is partial: #{e.message}")
        successful = false
      end

      successful
    end

    def default_installer_factories
      [
        ->(root:, manifest:) { Installers::ClaudeCode.new(root:, manifest:) },
        ->(root:, manifest:) { Installers::Codex.new(root:, manifest:) },
        ->(root:, manifest:) { Installers::Opencode.new(root:, manifest:) }
      ]
    end

    def restore_project_ownership
      return unless Process.euid.zero? && ENV.fetch("SUDO_UID", nil) && ENV["SUDO_GID"]

      uid = Integer(ENV.fetch("SUDO_UID"), 10)
      gid = Integer(ENV.fetch("SUDO_GID"), 10)
      paths = MANAGED_PATHS.filter_map do |relative_path|
        path = ProjectPath.validate!(root, File.join(root, relative_path))
        path if File.exist?(path)
      end
      paths.reverse_each { File.chown(uid, gid, _1) }
    end
  end
end
