---
title: Prevent filesystem aliases from bypassing agent ACL guards
problem_type: security_issue
component: agent-acl protected-path resolution and shell matching
date: 2026-09-02
severity: critical
tags:
  - path-canonicalization
  - symlink-bypass
  - hardlink-bypass
  - shell-guard
  - filesystem-alias
---

# Prevent filesystem aliases from bypassing agent ACL guards

## Problem

The generated Ruby and OpenCode guards originally compared shell operands to protected paths mostly by their text. A filesystem entry created before protection could therefore provide another name for the same file. For example, with `alias -> secret`, this command was allowed even though it modified `secret`:

```sh
chmod u+w alias && printf x > alias
```

The same identity gap affected hard links. OpenCode also missed several shell-equivalent spellings, including bracket globs, concatenated quote fragments, tilde paths, escaped literal quotes, and filenames containing `=`. Ruby missed ANSI-C quoted paths, and both guards treated commands such as `git diff --output=secret` and `less -O secret` as read-only despite their output options.

This was security-sensitive on non-root Linux, where removing write bits is the operating-system fallback and `chmod` through an alias changes the protected inode.

## Root cause

Path normalization and path identity are different concerns:

- `File.expand_path` and Node's `path.resolve` normalize lexical paths but do not identify hard links; `path.resolve` also does not follow symbolic links.
- Shell globs must be expanded before their results can be canonicalized.
- Shell token normalization must distinguish alternate spellings from literal filename characters.
- Treating every token containing `=` as an assignment discards valid complete filenames such as `a=b`.
- An executable-level read allowlist is insufficient when an otherwise read-only command supports options that write files or execute helpers.

The guard must compare what a path reaches, not only how the command spells it.

## Fix

Both guards now apply the same identity model:

1. Resolve paths relative to the project root.
2. Canonicalize existing paths through `realpath`.
3. Compare filesystem identity for hard links (`File.identical?` in Ruby; device and inode in JavaScript).
4. Expand supported shell globs and canonicalize every filesystem match.
5. Check both a complete `=` token and its assignment or option suffix.
6. Normalize supported quoted and tilde spellings; send ambiguous or unsupported forms through the existing fail-closed denial path.
7. Reject write-capable Git and `less` options before classifying a command as read-only.

Only `ENOENT` and `ENOTDIR` fall back to normalized lexical identity. Permission, loop, and I/O resolution failures remain errors so an active manifest denies the operation.

## Regression strategy

The Ruby and executable OpenCode tests cover:

- direct file tools and shell mutations through symbolic and hard links;
- wildcard and bracket-class globs that expand to aliases;
- concatenated quotes and current-user tilde paths;
- escaped literal quotes in real filenames;
- complete filenames containing `=` as well as assignment values;
- ANSI-C quoted paths and write-capable options on otherwise read-only commands;
- negative boundaries such as `LICENSE` versus `LICENSE.md`.

Future parser changes should run one conformance table through both generated guards. Unsupported shell evaluation must remain fail-closed, and operating-system protection should remain defense in depth because hook evaluation has an unavoidable time-of-check/time-of-use gap.

## Related files

- [Ruby guard](../../../lib/agent_acl/templates/guard.rb)
- [OpenCode guard](../../../lib/agent_acl/templates/opencode_plugin.js)
- [Guard regressions](../../../test/guard_test.rb)
- [Verification record](../../verification.md)
