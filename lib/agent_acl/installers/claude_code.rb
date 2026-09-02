# frozen_string_literal: true

module AgentAcl
  module Installers
    # Merges edit denials and a guard hook into Claude Code project settings.
    class ClaudeCode < Base
      CONFIG_PATH = ".claude/settings.json"
      HOOK_MATCHER = "Edit|Write|NotebookEdit|Bash"
      STATE_KEY = "claude_code"

      # Installs or repairs the managed configuration.
      def install
        with_json_path(config_path) do
          data = read_json(config_path)
          permissions = ensure_hash(data, "permissions")
          hooks = ensure_hash(data, "hooks")
          state = installer_state(STATE_KEY)

          permissions["deny"], owned_rules = reconcile_array(
            ensure_array(permissions, "deny"), managed_paths.map { "Edit(#{_1})" }, Array(state["deny_rules"])
          )
          desired_hooks = manifest.entries.empty? ? [] : [managed_hook]
          hooks["PreToolUse"], owned_hooks = reconcile_array(
            ensure_array(hooks, "PreToolUse"), desired_hooks, Array(state["hooks"])
          )

          prune_empty_hashes!(permissions, "deny")
          prune_empty_hashes!(hooks, "PreToolUse")
          prune_empty_hashes!(data, "permissions", "hooks")
          write_installer_state(STATE_KEY, ownership("deny_rules" => owned_rules, "hooks" => owned_hooks))
          write_json(config_path, data)
        end

        copy_template(guard_template_path, guard_path)
      end

      # Reconciles managed configuration with the current manifest.
      def sync
        install
      end

      def guard_template_path
        File.expand_path("../templates/guard.rb", __dir__)
      end

      private

      def config_path
        File.join(root, CONFIG_PATH)
      end

      def guard_path
        File.join(root, ".agent-acl.d", "guard.rb")
      end

      def ownership(values)
        values.reject { |_key, entries| entries.empty? }
      end

      def managed_hook
        {
          "matcher" => HOOK_MATCHER,
          "hooks" => [
            {
              "type" => "command",
              "command" => HOOK_COMMAND
            }
          ]
        }
      end
    end
  end
end
