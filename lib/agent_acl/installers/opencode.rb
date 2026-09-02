# frozen_string_literal: true

module AgentAcl
  module Installers
    # Merges OpenCode edit denials and installs the generated plugin.
    class Opencode < Base
      CONFIG_PATH = "opencode.json"
      PLUGIN_PATH = ".opencode/plugin/agent-acl.js"
      STATE_KEY = "opencode"

      # Installs or repairs the managed configuration and plugin.
      def install
        with_json_path(config_path) do
          data = read_json(config_path)
          permission = ensure_hash(data, "permission")
          state = installer_state(STATE_KEY)
          permission["edit"], owned_paths = reconcile_deny_hash(
            ensure_hash(permission, "edit"), managed_paths, Array(state["edit_paths"])
          )
          prune_empty_hashes!(permission, "edit")
          prune_empty_hashes!(data, "permission")
          write_installer_state(STATE_KEY, owned_paths.empty? ? {} : { "edit_paths" => owned_paths })
          write_json(config_path, data)
        end

        copy_template(plugin_template_path, plugin_path)
      end

      # Reconciles managed configuration with the current manifest.
      def sync
        with_json_path(config_path) do
          data = read_json(config_path)
          permission = ensure_hash(data, "permission")
          state = installer_state(STATE_KEY)
          permission["edit"], owned_paths = reconcile_deny_hash(
            ensure_hash(permission, "edit"), managed_paths, Array(state["edit_paths"])
          )
          prune_empty_hashes!(permission, "edit")
          prune_empty_hashes!(data, "permission")
          write_installer_state(STATE_KEY, owned_paths.empty? ? {} : { "edit_paths" => owned_paths })
          write_json(config_path, data)
        end

        if manifest.entries.empty?
          remove_file(plugin_path)
        else
          copy_template(plugin_template_path, plugin_path)
        end
      end

      def plugin_template_path
        File.expand_path("../templates/opencode_plugin.js", __dir__)
      end

      private

      def config_path
        File.join(root, CONFIG_PATH)
      end

      def plugin_path
        File.join(root, PLUGIN_PATH)
      end
    end
  end
end
