import fs from "node:fs"
import os from "node:os"
import path from "node:path"

const DENY_SENTENCE = "The user is not allowing changes to this file."
const INFRASTRUCTURE_PATHS = [
  [".agent-acl", false],
  [".agent-acl.d", true],
  [".claude/settings.json", false],
  [".codex/hooks.json", false],
  ["opencode.json", false],
]
const READ_ONLY_COMMANDS = new Set([
  "cat",
  "basename",
  "cmp",
  "diff",
  "dirname",
  "echo",
  "file",
  "grep",
  "head",
  "less",
  "ls",
  "md5",
  "more",
  "printf",
  "pwd",
  "readlink",
  "realpath",
  "rg",
  "shasum",
  "stat",
  "strings",
  "sum",
  "tail",
  "test",
  "true",
  "type",
  "wc",
  "which",
  "[",
])
const READ_ONLY_GIT_SUBCOMMANDS = new Set(["blame", "diff", "log", "show", "status"])
const UNSAFE_GIT_READ_OPTIONS = new Set(["--ext-diff", "--textconv"])
const GIT_OUTPUT_OPTION = /^--output(?:=|$)/
const LESS_OUTPUT_OPTION = /^(?:-[oO]|--(?:log-file|LOG-FILE)(?:=|$))/
const PATH_SCOPED_MUTATORS = new Set([
  "agent-acl", "chattr", "chflags", "chmod", "cp", "dd", "echo", "find", "install", "ln", "mkdir",
  "mv", "printf", "rm", "rmdir", "rsync", "tee", "touch", "truncate", "unlink",
])
const HARMLESS_SHELL_BUILTINS = new Set(["cd", "export", "popd", "pushd", "unset"])
const SPLIT_COMMANDS = /\s*(?:&&|\|\||\||;|\n)\s*/
const REDIRECTION = /(^|[^<])>>?|[12]>>?/
const UNSAFE_SHELL_SYNTAX = /`|\$\(|[<>]|(?<!&)&(?!&)/
const AMBIGUOUS_SHELL_SYNTAX = /`|\$\(|\$["']|\\["']|(?<!&)&(?!&)|[{}]/
const SHELL_VARIABLE = /\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))/g
const SHELL_ASSIGNMENT = /(?:^|[;&|]\s*)([A-Za-z_]\w*)=(?:"([^"]*)"|'([^']*)'|([^\s;&|]+))/g

export const AgentAclPlugin = async ({ worktree, directory }) => {
  const root = canonicalPath(path.resolve(worktree || directory || process.cwd()))

  return {
    "tool.execute.before": async (input, output) => {
      try {
        const hits = protectedHits(root, input, output)
        if (hits.length === 0) return

        const command = shellCommand(output)
        if (command && readOnly(command)) return

        throw new Error(denyReason(hits[0].displayPath))
      } catch (error) {
        if (error instanceof Error && error.message.includes(DENY_SENTENCE)) throw error
        throw guardError()
      }
    },
  }
}

function protectedHits(root, input, output) {
  const protectedPaths = loadProtectedPaths(root)
  if (protectedPaths.length === 0) return []

  const hits = []
  for (const candidate of targets(root, input, output, protectedPaths)) {
    const match = protectedPaths.find((entry) => entry.match(candidate))
    if (match && !hits.find((entry) => entry.absolutePath === match.absolutePath)) hits.push(match)
  }
  return hits
}

function targets(root, input, output, protectedPaths) {
  switch (input.tool) {
    case "edit":
    case "write":
    case "patch": {
      const filePath = output.args?.filePath
      if (!filePath) throw guardError()
      return [filePath]
    }
    case "apply_patch":
      return applyPatchTargets(output.args?.patchText, protectedPaths)
    case "bash": {
      const command = output.args?.command
      if (!command) throw guardError()
      return shellTargets(root, command, protectedPaths)
    }
    default:
      return []
  }
}

function applyPatchTargets(patchText, protectedPaths) {
  const patch = patchText || ""
  const matches = []
  for (const line of patch.split("\n")) {
    const matchedPath =
      line.match(/^\*\*\* (?:Update|Delete|Add) File: (.+)$/)?.[1] ||
      line.match(/^\*\*\* Move to: (.+)$/)?.[1]
    if (matchedPath) matches.push(matchedPath)
  }

  return matches.length > 0 ? matches : mentionedPaths(patch, protectedPaths)
}

function mentionedPaths(text, protectedPaths) {
  return protectedPaths
    .filter((entry) => pathMentioned(text, entry.displayPath) || pathMentioned(text, entry.absolutePath))
    .map((entry) => entry.absolutePath)
}

function shellTargets(root, command, protectedPaths) {
  if (AMBIGUOUS_SHELL_SYNTAX.test(command)) return protectedPaths.map((entry) => entry.absolutePath)

  const [expanded, unknownVariable] = expandShellVariables(command)
  if (unknownVariable) return protectedPaths.map((entry) => entry.absolutePath)

  if (expanded.split(SPLIT_COMMANDS).some(unboundedEffects)) {
    return protectedPaths.map((entry) => entry.absolutePath)
  }

  const tokens = shellTokens(expanded)
  if (mutatingGit(tokens)) return protectedPaths.map((entry) => entry.absolutePath)

  return protectedPaths
    .filter((entry) => shellPathMatch(root, entry, expanded, tokens))
    .map((entry) => entry.absolutePath)
}

function expandShellVariables(command) {
  const variables = new Map()
  for (const match of command.matchAll(SHELL_ASSIGNMENT)) {
    variables.set(match[1], match[2] || match[3] || match[4] || "")
  }

  let unknown = false
  const expanded = command.replace(SHELL_VARIABLE, (_match, braced, bare) => {
    const name = braced || bare
    if (variables.has(name)) return variables.get(name)
    unknown = true
    return ""
  })
  return [expanded, unknown]
}

function shellTokens(command) {
  return command
    .split(SPLIT_COMMANDS)
    .flatMap((part) => part.match(/(?:[^\s"'\\]+|\\.|"[^"]*"|'[^']*')+/g) || [])
    .map((token) => token.replace(/["']/g, "").replace(/\\(.)/g, "$1"))
}

function shellPathMatch(root, entry, command, tokens) {
  if (pathMentioned(command, entry.displayPath) || pathMentioned(command, entry.absolutePath)) return true

  return tokens.some((token) => {
    const candidate = token.replace(/^\(/, "").replace(/\)$/, "")
    return globMatches(candidate, entry.displayPath) ||
      globMatches(path.basename(candidate), path.basename(entry.displayPath)) ||
      shellAncestor(root, candidate, entry)
  })
}

function mutatingGit(tokens) {
  const gitIndex = tokens.findIndex((token) => path.basename(token) === "git")
  return gitIndex >= 0 && !READ_ONLY_GIT_SUBCOMMANDS.has(tokens[gitIndex + 1])
}

function unboundedEffects(command) {
  if (readOnly(command)) return false

  const words = shellTokens(command)
  if (words.length === 0 || words.every((word) => /^[A-Za-z_]\w*=/.test(word))) return false

  const executable = path.basename(words[0])
  return !HARMLESS_SHELL_BUILTINS.has(executable) && !PATH_SCOPED_MUTATORS.has(executable)
}

function shellAncestor(root, token, entry) {
  const candidates = [token]
  const equals = token.indexOf("=")
  if (equals >= 0) candidates.push(token.slice(equals + 1))
  const ancestors = entry.displayPath.split(/[\\/]/).slice(0, -1)

  return [...new Set(candidates)].some((candidate) => {
    if (!candidate || candidate.startsWith("-")) return false

    const aliasesProtectedPath = expandGlob(root, candidate).some((expanded) => {
      const absolute = canonicalPath(expanded)
      return absolute === entry.absolutePath || sameFile(absolute, entry.absolutePath) ||
        entry.absolutePath.startsWith(`${absolute}${path.sep}`)
    })
    return aliasesProtectedPath || ancestors.some((_part, index) =>
      globMatches(candidate, ancestors.slice(0, index + 1).join(path.sep)))
  })
}

function globMatches(pattern, value) {
  const parts = []
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index]
    if (character === "*") {
      parts.push(".*")
    } else if (character === "?") {
      parts.push(".")
    } else if (character === "[") {
      const closing = pattern.indexOf("]", index + 1)
      if (closing <= index + 1) return true

      let contents = pattern.slice(index + 1, closing)
      const negated = contents.startsWith("!") || contents.startsWith("^")
      if (negated) contents = contents.slice(1)
      if (!contents || /[\[\\]/.test(contents)) return true

      parts.push(`[${negated ? "^" : ""}${contents}]`)
      index = closing
    } else {
      parts.push(character.replace(/[.+^${}()|[\]\\]/g, "\\$&"))
    }
  }

  try {
    return new RegExp(`^${parts.join("")}$`).test(value)
  } catch {
    return true
  }
}

function pathMentioned(text, candidate) {
  const escaped = candidate.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  return new RegExp(`(?:^|[\\s"'=/])${escaped}(?:$|[\\s"'/:])`).test(text)
}

function loadProtectedPaths(root) {
  const manifestPath = path.join(root, ".agent-acl")
  if (!fs.existsSync(manifestPath)) return []

  const lines = fs.readFileSync(manifestPath, "utf8").split(/\r?\n/).filter(Boolean)
  const manifestPaths = lines.map((line) => {
    const fields = line.split("\t")
    const [operation, mode, relativePath] = fields
    const valid = fields.length === 3 && operation === "edit" && /^[0-7]{3,4}$/.test(mode) && relativePath
    if (!valid) throw guardError()

    return buildProtectedPath(root, relativePath, false)
  })

  if (manifestPaths.length === 0) return []

  return manifestPaths.concat(
    INFRASTRUCTURE_PATHS.map(([relativePath, directory]) => buildProtectedPath(root, relativePath, directory)),
  )
}

function buildProtectedPath(root, displayPath, directory) {
  const absolutePath = canonicalPath(path.resolve(root, displayPath))
  return {
    absolutePath,
    displayPath,
    directory,
    match(candidate) {
      const expanded = canonicalPath(path.resolve(root, candidate))
      return expanded === absolutePath || sameFile(expanded, absolutePath) ||
        (directory && expanded.startsWith(`${absolutePath}${path.sep}`))
    },
  }
}

function canonicalPath(candidate) {
  try {
    return fs.realpathSync.native(candidate)
  } catch (error) {
    if (error?.code === "ENOENT" || error?.code === "ENOTDIR") return path.resolve(candidate)
    throw error
  }
}

function sameFile(left, right) {
  try {
    const leftStat = fs.statSync(left)
    const rightStat = fs.statSync(right)
    return leftStat.dev === rightStat.dev && leftStat.ino === rightStat.ino
  } catch (error) {
    if (error?.code === "ENOENT" || error?.code === "ENOTDIR") return false
    throw error
  }
}

function expandGlob(root, pattern) {
  const absolute = resolveShellPath(root, pattern)
  if (!/[*?\[]/.test(pattern)) return [absolute]

  const volume = path.parse(absolute).root
  const segments = absolute.slice(volume.length).split(path.sep).filter(Boolean)
  return segments.reduce((parents, segment) => parents.flatMap((parent) => {
    if (!/[*?\[]/.test(segment)) return [path.join(parent, segment)]

    try {
      return fs.readdirSync(parent)
        .filter((entry) => globMatches(segment, entry))
        .map((entry) => path.join(parent, entry))
    } catch (error) {
      if (error?.code === "ENOENT" || error?.code === "ENOTDIR") return []
      throw error
    }
  }), [volume])
}

function resolveShellPath(root, candidate) {
  if (candidate === "~") return os.homedir()
  if (candidate.startsWith(`~${path.sep}`)) return path.resolve(os.homedir(), candidate.slice(2))
  if (candidate.startsWith("~")) throw guardError()

  return path.resolve(root, candidate)
}

function shellCommand(output) {
  return output.args?.command || null
}

function readOnly(command) {
  if (REDIRECTION.test(command) || UNSAFE_SHELL_SYNTAX.test(command)) return false
  return command
    .split(SPLIT_COMMANDS)
    .map((part) => part.trim())
    .filter(Boolean)
    .every(readOnlyCommand)
}

function readOnlyCommand(command) {
  const words = command.trim().split(/\s+/)
  if (words.length === 0) return false

  const executable = path.basename(words[0])
  if (executable === "git") return readOnlyGit(words)
  if (executable === "less") return readOnlyLess(words)

  return READ_ONLY_COMMANDS.has(executable)
}

function readOnlyGit(words) {
  return READ_ONLY_GIT_SUBCOMMANDS.has(words[1]) && words.slice(2).every((word) =>
    !UNSAFE_GIT_READ_OPTIONS.has(word) && !GIT_OUTPUT_OPTION.test(word))
}

function readOnlyLess(words) {
  return words.slice(1).every((word) => !LESS_OUTPUT_OPTION.test(word))
}

function denyReason(displayPath) {
  return `BLOCKED by agent-acl: ${DENY_SENTENCE} This is a deliberate policy, not an error. Do not retry, and do not work around it - no shell tricks, no scripts, no renaming, copying, or recreating the file. If your task requires changing this file, stop and ask the user to run: agent-acl allow edit ${displayPath}.`
}

function guardError() {
  return new Error(`agent-acl guard error. ${denyReason(".agent-acl")}`)
}
