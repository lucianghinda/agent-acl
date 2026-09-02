# frozen_string_literal: true

require "fileutils"
require "json"
require "tempfile"

module AgentAcl
  # Project-local configuration installers for supported coding agents.
  module Installers
    # Shared atomic JSON, template, and ownership-state operations.
    class Base
      HOOK_COMMAND = "ruby .agent-acl.d/guard.rb"
      INFRA_PATHS = [
        ".agent-acl",
        ".agent-acl.d/guard.rb",
        ".agent-acl.d/installers.json",
        ".claude/settings.json",
        ".codex/hooks.json",
        "opencode.json"
      ].freeze
      STATE_PATH = ".agent-acl.d/installers.json"

      # @param root [String] project root
      # @param manifest [AgentAcl::Manifest]
      def initialize(root:, manifest:)
        @root = File.realpath(root)
        @manifest = manifest
      end

      private

      attr_reader :root, :manifest

      def read_json(path)
        validate_project_path!(path)
        return {} unless File.file?(path)

        parsed = JSON.parse(File.read(path))
        fail Error, "#{relative_path(path)} must contain a JSON object" unless parsed.is_a?(Hash)

        parsed
      rescue JSON::ParserError
        raise Error, "#{relative_path(path)} is not valid JSON"
      end

      def write_json(path, data)
        write_text(path, "#{JSON.pretty_generate(data)}\n")
      end

      def write_text(path, contents)
        validate_project_path!(path)
        FileUtils.mkdir_p(File.dirname(path))
        validate_project_path!(path)
        return if File.file?(path) && File.read(path) == contents

        mode = File.file?(path) ? File.stat(path).mode & 0o7777 : 0o644
        Tempfile.create([".#{File.basename(path)}.", ".tmp"], File.dirname(path)) do |file|
          file.write(contents)
          file.flush
          file.fsync
          File.chmod(mode, file.path)
          File.rename(file.path, path)
        end
      end

      def copy_template(source, destination)
        write_text(destination, File.read(source))
      end

      def remove_file(path)
        validate_project_path!(path)
        FileUtils.rm_f(path)
      end

      def ensure_hash(parent, key)
        case parent[key]
        when nil
          parent[key] = {}
        when Hash
          parent[key]
        else
          fail Error, "#{key} in #{relative_path_for_json(parent)} must be an object"
        end
      end

      def ensure_array(parent, key)
        case parent[key]
        when nil
          parent[key] = []
        when Array
          parent[key]
        else
          fail Error, "#{key} in #{relative_path_for_json(parent)} must be an array"
        end
      end

      def managed_paths
        return [] if manifest.entries.empty?

        (manifest.entries.map(&:path) + INFRA_PATHS).uniq
      end

      def installer_state(key)
        load_installer_state.fetch(key, {})
      end

      def write_installer_state(key, value)
        state = load_installer_state
        value.empty? ? state.delete(key) : state[key] = value
        state.empty? ? remove_file(installer_state_path) : write_json(installer_state_path, state)
      end

      def reconcile_array(existing, desired, previously_owned)
        merged = existing.dup
        previously_owned.each { remove_last(merged, _1) }
        owned = desired.reject { merged.include?(_1) }
        [merged + owned, owned]
      end

      def reconcile_deny_hash(existing, desired_paths, previously_owned)
        merged = existing.dup
        previously_owned.each { merged.delete(_1) }
        owned = desired_paths.reject { merged.key?(_1) }
        owned.each { merged[_1] = "deny" }
        [merged, owned]
      end

      def relative_path(path)
        File.expand_path(path).delete_prefix("#{root}/")
      end

      def relative_path_for_json(_parent)
        @current_json_path || "<config>"
      end

      def with_json_path(path)
        previous = @current_json_path
        @current_json_path = relative_path(path)
        yield
      ensure
        @current_json_path = previous
      end

      def prune_empty_hashes!(data, *keys)
        keys.each do |key|
          next unless data[key].respond_to?(:empty?) && data[key].empty?

          data.delete(key)
        end
      end

      def validate_project_path!(path)
        ProjectPath.validate!(root, path)
      end

      def load_installer_state
        read_json(installer_state_path)
      end

      def installer_state_path
        File.join(root, STATE_PATH)
      end

      def remove_last(items, item)
        index = items.rindex(item)
        items.delete_at(index) if index
      end
    end
  end
end
