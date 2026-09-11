# Scanner CLI

The current SpaceMind vertical slice is a read-only Rust scanner with deterministic recommendation rules and exact duplicate detection. It does not delete, archive, rename, or modify files.

## Run a scan

From the repository root:

```bash
cargo run -p spacemind-cli -- scan ~/Downloads --top 20
```

Launch without arguments for the interactive terminal interface:

```bash
cargo run -p spacemind-cli --
```

The interface centers itself within wide terminals. Navigate its folder selector with the
arrow keys or `j`/`k`, press `Enter` to scan the selected folder, press `c` to type a custom
path, and press `q` to leave safely. Narrow terminals use the available width and shorten
long paths from the beginning so the most useful final path components remain visible.

Human-readable reports use numbered sections in a stable order: overview, safety,
recommendations, relationships, duplicates, and largest items. Recommendation and relationship
records use the same labeled fields throughout, while long paths and explanations wrap inside
the report canvas. Use `--format json` when another program needs to parse the complete result.

Limit the human-readable list to items above a given size:

```bash
cargo run -p spacemind-cli -- scan ~/Downloads --min-size 100MB
```

Supported size suffixes are `B`, `KB`, `MB`, `GB`, `TB`, `KiB`, `MiB`, `GiB`, and `TiB`.

For structured output:

```bash
cargo run -p spacemind-cli -- scan ~/Downloads --format json
```

JSON output includes the complete scan, warnings, metadata, deterministic findings, and duplicate report. It also reports matched ignored paths, protected-item counts, and recommendations withheld by the safety policy. It is intended to become the boundary consumed by SQLite persistence and the desktop interface.

## Protected paths and ignore rules

Protection and ignoring have deliberately different meanings:

- `--protect` scans the matching path and includes it in storage totals, but suppresses cleanup recommendations for it and every descendant. Protected duplicate copies remain visible as evidence and are excluded from unsafe recovery estimates.
- `--ignore` prunes the matching path before metadata collection. Its contents are absent from totals, rules, and duplicate detection.

Both options are repeatable and accept exact paths or `*`, `?`, and `**` wildcard patterns. Quote wildcard rules so the shell does not expand them before SpaceMind receives them:

```bash
spacemind scan ~ --protect ~/Documents --ignore "**/.git/**" --ignore "node_modules"
```

On Linux, SpaceMind protects standard operating-system locations such as `/etc`, `/usr`, `/boot`, and `/var/lib` by default. On Windows, it protects Windows, Program Files, and ProgramData locations discovered from the environment. Use `--no-default-protections` only when you intentionally want recommendations inside those locations. This option does not disable explicit `--protect` rules.

## Exact duplicate detection

SpaceMind first groups nonempty files by logical size. Only size groups containing at least two separately allocated files are hashed. Matching BLAKE3 hashes form exact duplicate groups.

The CLI hashes files of at least 1 MiB by default. Change that threshold when smaller duplicates matter:

```bash
cargo run -p spacemind-cli -- scan ~/Downloads --duplicate-min-size 1B
```

Hashing is streamed in bounded memory. SpaceMind verifies file identity, length, and modification time before and after hashing. Unreadable, replaced, deleted, or changing candidates produce warnings and are excluded from duplicate groups.

Hard-linked names share a physical file identity. They appear as aliases in a matching group but are hashed once and never counted as separately recoverable space. Potential recovery retains one physical copy and uses allocated disk size when the operating system exposes it.

## Rules

The initial rule engine identifies:

- Node.js `node_modules` dependencies
- Rust `target` directories beside a `Cargo.toml` manifest
- Gradle caches and downloaded Gradle distributions
- Android Virtual Device directories
- VirtualBox, VMware, QEMU, and common virtual-disk formats
- Old ISO images, application installers, and archives
- User caches and known Linux or Windows operating-system caches
- Generic `build` and `dist` directories
- Items above the configurable large-item threshold

The classifier uses filesystem context where possible. For example, a directory named
`target` receives the Rust classification only when a sibling `Cargo.toml` was found.
VM bundles and Android emulators are high risk and suggested for archiving because they
may contain unique user state. Generated dependencies and build caches receive lower risk.

Change rule thresholds from the CLI:

```bash
cargo run -p spacemind-cli -- scan ~/Downloads \
  --large-threshold 2GiB \
  --old-days 240
```

Findings are evidence for review, not deletion decisions. A large item is assigned high
risk because size alone does not establish that it is replaceable.

## Relationship detection

After scanning and duplicate hashing, SpaceMind connects related items using deterministic
filesystem evidence:

- Archives with sibling directories that share the extracted name
- Installers with sibling application directories sharing a normalized product name
- `node_modules`, Rust `target`, `build`, and `dist` with source-project manifests
- VM disks with VirtualBox, VMware, or OVF configuration
- VM packages with matching imported VM directories in the scanned location
- Android `.avd` directories with their matching `.ini` configuration
- Exact duplicate files with the same size and BLAKE3 fingerprint

Relationships have their own confidence and evidence in human and JSON output. Matching
relationships are also added to recommendation explanations. They do not authorize deletion.
An installer-to-directory match is deliberately described as related context; it does not prove
that the application is installed.

## Filesystem behavior

- Symbolic links are recorded but never followed.
- Traversal stays on the starting filesystem by default.
- Use `--cross-filesystems` to explicitly include mounted filesystems beneath the root.
- Permission failures and files that disappear during scanning become warnings instead of aborting the whole scan.
- Logical size records the visible byte length of every file name.
- Allocated size records disk blocks where the platform exposes them.
- Hard-linked files have one physical identity and are counted once in allocated directory totals.

## Tests

Run the workspace tests with:

```bash
cargo test --workspace --locked
```

The suite covers nested size aggregation, logical and allocated sizes, hard links, empty directories, symlink safety, size parsing, deterministic rules, exact duplicates, changed and unreadable candidates, JSON serialization, and the compiled CLI process.
