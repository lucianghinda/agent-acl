# Verification

Verification date: 2026-09-03

## Automated suite

The portable Minitest suite and RuboCop run with:

```console
bundle exec rake
```

Current result: `134 runs, 1582 assertions, 0 failures, 0 errors, 0 skips`; RuboCop reports no offenses.

The suite covers the manifest, CLI validation and idempotence, generated Ruby and OpenCode guard contracts (including symbolic-link, hard-link, and glob aliases), installer merge and ownership behavior, source and installed package executables, Zeitwerk eager loading, Git-independent packaging, reproducible YARD and LLM documentation, fail-fast release preparation, and mocked OS branches. The macOS host also runs the real immutable-file integration test.

The generated OpenCode plugin is syntax-checked separately during release verification:

```console
node --check lib/agent_acl/templates/opencode_plugin.js
```

## macOS integration

Verified on the development host with the real `chflags uchg` implementation:

- block removes write bits and applies `uchg`;
- direct write, delete, rename, and chmod fail;
- read and execute succeed;
- allow removes the flag and restores mode `0755`;
- the complete CLI creates all three project-local agent configurations and generated guards;
- re-block repairs the protection and preserves the first recorded mode.

## Linux integration

Run from macOS through the Ruby Docker harness:

```console
ruby test/linux/run.rb
```

Result: `Linux OS guard and sudo ownership checks passed`.

The harness verifies:

- root applies `chattr +i` and blocks non-root write, delete, and rename;
- a non-root allow refuses with `AgentAcl::NeedsSudo` and leaves protection intact;
- a root allow restores the recorded mode;
- a non-root block removes write bits, reports incomplete delete/rename protection, and prints the sudo command;
- a root CLI run returns every generated manifest/config path to `SUDO_UID:SUDO_GID`.

## Hook contracts

The generated Ruby guard is tested as a standalone subprocess with Claude Code and Codex-shaped
payloads. Confirmed modification denials use the `hookSpecificOutput` / `PreToolUse` envelope and
include:

> The user is not allowing changes to this file.

Commands whose effects cannot be determined use a separate fail-closed reason and do not suggest
allowing an unrelated manifest path. The suite covers unknown executables, quote-aware shell
segmentation, malformed shell input, executable allowlisting, accurate protected-path reporting,
shell comments, source/destination-aware commands, and protected output-redirection targets.

The contract was checked against the current official sources:

- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [Codex PreToolUse input schema](https://github.com/openai/codex/blob/main/codex-rs/hooks/schema/generated/pre-tool-use.command.input.schema.json)
- [Codex PreToolUse output schema](https://github.com/openai/codex/blob/main/codex-rs/hooks/schema/generated/pre-tool-use.command.output.schema.json)
- [OpenCode plugins](https://opencode.ai/docs/plugins/)

## Manual real-agent acceptance

The automated suite does not launch authenticated agent clients. Before publishing, use an isolated project to verify Claude Code, Codex CLI, and OpenCode against a protected test file. Ask each agent to read the file, then attempt an edit, deletion, rename, `sed -i`, immutable-flag removal, and `agent-acl allow`; repeat after a fresh session. Every mutation should be denied with the applicable modification or unanalysable-command reason, and the file should remain unchanged.
