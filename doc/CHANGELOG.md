## [Unreleased]

## [0.1.0] - 2026-09-02

- Load library constants with Zeitwerk and verify eager loading from an isolated gem install.
- Add generated Markdown API documentation and a packaged `llm.txt` entry point.
- Add `bin/prepare_release` for fail-fast validation, documentation generation, and gem building.
- Add Git-independent packaging, documentation, release-tooling, and executable regression tests.
- Correct `bin/console` and provide a Ruby-native `bin/setup`.
- Deny protected-file mutations through filesystem aliases, encoded shell paths, and write-capable command options.
- Make `agent-acl list` describe each entry as an edit block.
- Add `block edit`, `allow edit`, `list`, and `version` commands.
- Protect files through project-local Claude Code, Codex CLI, and OpenCode configuration.
- Add macOS immutable flags and Linux write-bit/immutable-attribute enforcement.
- Preserve original file modes and unrelated agent configuration.
