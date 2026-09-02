# Class AgentAcl::Manifest <a id="class-AgentAcl-Manifest"></a>

|  |  |
| --- | --- |
| **Inherits** | Object |
| **Defined in** | lib/agent_acl/manifest.rb |

Reads and atomically writes the project-local <code>.agent-acl</code>
manifest.

## Constants
### `FILENAME` <a id="constant-FILENAME"></a> <a id="FILENAME-constant"></a>
Not documented.

## Attributes
### `entries` [R] <a id="attribute-i-entries"></a> <a id="entries-instance_method"></a>
Returns the value of attribute entries.

### `removed_entries` [R] <a id="attribute-i-removed_entries"></a> <a id="removed_entries-instance_method"></a>
Returns the value of attribute removed_entries.

### `root` [R] <a id="attribute-i-root"></a> <a id="root-instance_method"></a>
Returns the value of attribute root.

## Public Class Methods
### `load(root, err: = nil)` <a id="method-c-load"></a> <a id="load-class_method"></a>
Loads a project's manifest, skipping malformed lines with a warning.
- **@param** `root` [String]
- **@param** `err` [IO, nil]
- **@return** [Manifest]

## Public Instance Methods
### `absolute_path(entry_path)` <a id="method-i-absolute_path"></a> <a id="absolute_path-instance_method"></a>
- **@return** [String] absolute path for a manifest entry

### `add(entry_path, mode:)` <a id="method-i-add"></a> <a id="add-instance_method"></a>
Adds a path while preserving the first recorded mode.
- **@return** [Entry]

### `initialize(root)` <a id="method-i-initialize"></a> <a id="initialize-instance_method"></a>
- **@param** `root` [String]
- **@return** [Manifest] a new instance of Manifest

### `path()` <a id="method-i-path"></a> <a id="path-instance_method"></a>
- **@return** [String] absolute manifest path

### `protected?(entry_path)` <a id="method-i-protected-3F"></a> <a id="protected?-instance_method"></a>
- **@return** [Boolean] whether the path has a manifest entry

### `relative_path_for(entry_path)` <a id="method-i-relative_path_for"></a> <a id="relative_path_for-instance_method"></a>
- **@return** [String] project-relative path for an entry

### `remove(entry_path)` <a id="method-i-remove"></a> <a id="remove-instance_method"></a>
Removes and records an existing entry for installer reconciliation.
- **@return** [Entry, nil]

### `write()` <a id="method-i-write"></a> <a id="write-instance_method"></a>
Atomically persists the current entries.
- **@return** [void]
