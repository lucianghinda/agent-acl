# frozen_string_literal: true

module AgentAcl
  module Installers
    # Merges the generated guard into the Codex project hook configuration.
    class Codex < Base
      CONFIG_PATH = ".codex/hooks.json"
      HOOK_MATCHER = "apply_patch|Bash"
      STATE_KEY = "codex"

      # Installs or repairs the managed hook.
      def install
        write_config(add_managed_hook: true)
        copy_template(guard_template_path, guard_path)
      end

      # Reconciles the managed hook with the current manifest.
      def sync
        write_config(add_managed_hook: !manifest.entries.empty?)
        copy_template(guard_template_path, guard_path)
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

      def write_config(add_managed_hook:)
        with_json_path(config_path) do
          data = read_json(config_path)
          hooks = ensure_hash(data, "hooks")
          state = installer_state(STATE_KEY)
          desired_hooks = add_managed_hook ? [managed_hook] : []
          pre_tool_use, owned_hooks = reconcile_array(
            ensure_array(hooks, "PreToolUse"), desired_hooks, Array(state["hooks"])
          )
          hooks["PreToolUse"] = pre_tool_use unless pre_tool_use.empty?
          hooks.delete("PreToolUse") if pre_tool_use.empty?
          prune_empty_hashes!(data, "hooks")
          write_installer_state(STATE_KEY, owned_hooks.empty? ? {} : { "hooks" => owned_hooks })
          write_json(config_path, data)
        end
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
