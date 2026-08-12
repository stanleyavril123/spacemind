# Scanner CLI

The current SpaceMind vertical slice is a read-only Rust scanner with deterministic recommendation rules and exact duplicate detection. It does not delete, archive, rename, or modify files.

## Run a scan

From the repository root:

```bash
cargo run -p spacemind-cli -- scan ~/Downloads --top 20
```

Limit the human-readable list to items above a given size:

```bash
cargo run -p spacemind-cli -- scan ~/Downloads --min-size 100MB
```

Supported size suffixes are `B`, `KB`, `MB`, `GB`, `TB`, `KiB`, `MiB`, `GiB`, and `TiB`.

For structured output:

```bash
cargo run -p spacemind-cli -- scan ~/Downloads --format json
```

JSON output includes the complete scan, warnings, metadata, deterministic findings, and duplicate report. It is intended to become the boundary consumed by SQLite persistence and the desktop interface.

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

- Items above the configurable large-item threshold
- Old installer and disk-image formats
- Old archive formats
- `.cache` and Gradle cache directories
- `node_modules`, `target`, `build`, and `dist` directories

Change rule thresholds from the CLI:

```bash
cargo run -p spacemind-cli -- scan ~/Downloads \
  --large-threshold 2GiB \
  --old-days 240
```

Findings are evidence for review, not deletion decisions. A large item is assigned high risk because size alone does not establish that it is replaceable.

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
