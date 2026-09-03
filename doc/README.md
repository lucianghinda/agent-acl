# agent-acl

`agent-acl` lets a project owner mark individual files as off-limits to coding agents without making them unreadable or unexecutable.

It applies two complementary protections:

- Project-local rules for Claude Code, Codex CLI, and OpenCode deny edit tools and unsafe shell commands.
- An operating-system lock blocks writes by processes that bypass agent hooks.

No global agent configuration is changed. The gem uses Zeitwerk 2.8 for loading; the generated project guard remains a standalone standard-library Ruby script.

## Installation

Add the gem to an application's `Gemfile`:

```ruby
gem "agent-acl"
```

Then run `bundle install`, or install it directly:

```console
gem install agent-acl
```

Ruby 3.2 or newer is required. macOS and Linux are supported; Windows is not.

## Usage

Run commands from the project root. Targets must be regular files inside that project; directories, symlinks, and names containing agent-rule metacharacters are refused.

Protect one or more files:

```console
agent-acl block edit LICENSE "docs/release notes.md"
```

See the current policy:

```console
$ agent-acl list
edit blocked -> LICENSE
edit blocked -> docs/release notes.md
```

Restore edits, deletion, renaming, and the file's original mode:

```console
agent-acl allow edit LICENSE
```

Both `block` and `allow` are idempotent. Re-blocking repairs missing layers while preserving the mode recorded by the first block.

## What is written

The project receives these files as needed:

```text
.agent-acl                         protected paths and original modes
.agent-acl.d/guard.rb              Claude Code and Codex hook
.agent-acl.d/installers.json       ownership of entries added to agent configs
.claude/settings.json              Claude Code rules and hook
.codex/hooks.json                  Codex hook
opencode.json                      OpenCode edit-deny rules
.opencode/plugin/agent-acl.js      OpenCode shell and tool guard
```

Existing JSON keys and non-agent-acl hook entries are preserved. Installer ownership is recorded separately so cleanup never removes an identical rule that existed before agent-acl. When the last file is allowed again, agent-acl removes its owned per-file rules and hook registrations. The generated guard files may then be deleted if the project no longer needs them.

The manifest is deliberately plain text and suitable for version control:

```text
edit\t0644\tLICENSE
edit\t0755\tbin/release
```

Projects can explicitly trust additional read-only executables by listing their basenames, one per
line, in `.agent-acl.d/executables.allow`. Blank lines and lines beginning with `#` are ignored.
Allowlisting is a deliberate trust decision: the Ruby hook permits that executable to receive a
protected path, but known mutators such as `rm`, `mv`, and `tee` remain denied even if listed.

## Operating-system behavior

On macOS, agent-acl removes write bits and applies the user immutable flag with `chflags uchg`. Reading and executing still work. The file owner can revert the flag without sudo.

On Linux, agent-acl always removes write bits. Full delete and rename protection requires `chattr +i`, which normally needs `CAP_LINUX_IMMUTABLE`. A non-root block still succeeds but prints the exact gap and a `sudo agent-acl block edit ...` command. Allowing a file with `+i` likewise requires sudo.

When invoked through sudo, generated project files are returned to `SUDO_UID:SUDO_GID` ownership.

## Security boundary and limits

`agent-acl` protects against accidental or instruction-driven agent changes; it is not a tamper-proof boundary against a malicious process running as the same OS user. That user can remove macOS flags, and root can remove Linux immutable attributes.

The generated Ruby hook policy is deliberately fail-closed while any file is protected. Read-only commands are
allowed, and path-scoped mutators are allowed when their write targets are provably disjoint from
protected paths. Commands with unknown effects are allowed when they do not reference a protected
path; otherwise they are denied as unanalysable unless their executable is explicitly trusted in
`.agent-acl.d/executables.allow`. Malformed or genuinely ambiguous shell input is always denied.

Version 0.1 protects individual files from edits, replacement, deletion, renaming, and protection-lifting commands. It does not:

- deny reads;
- accept directories or globs;
- support Windows or agents other than Claude Code, Codex CLI, and OpenCode;
- intercept arbitrary writes performed by an MCP server, though the OS layer still blocks the resulting file write;
- prevent Dropbox or another sync client from reporting conflicts with immutable files.

## Development

Install the development dependencies and run the portable test and lint suite:

```console
bin/setup
bundle exec rake
```

The macOS integration test runs automatically on macOS. Linux immutable-attribute checks live in `test/linux/` and require a filesystem plus privileges that support `chattr +i`. Real-agent acceptance evidence and the pinned versions are documented in `docs/verification.md`.

Run the Linux harness directly on Linux as root, or from macOS through Docker:

```console
ruby test/linux/run.rb
```

Generate the packaged Markdown API documentation and its LLM-oriented entry point:

```console
bundle exec rake yard
ruby bin/generate_llm.rb
```

The generated API starts at `doc/AgentAcl.md`; `llm.txt` exposes the same documentation with package-root-relative links. Prepare a release with one fail-fast command that runs tests and lint, regenerates both documentation forms, and builds the gem:

```console
bin/prepare_release
```

## License

The gem is available under the [MIT License](LICENSE.txt).
