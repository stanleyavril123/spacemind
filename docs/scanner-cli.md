# Scanner CLI

The first SpaceMind vertical slice is a read-only Rust scanner with deterministic recommendation rules. It does not delete, archive, rename, or modify files.

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

JSON output includes the complete scan, warnings, metadata, and all deterministic findings. It is intended to become the boundary consumed by SQLite persistence and the desktop interface.

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
- Sizes represent logical file length.
- Hard-linked names are currently counted separately.

## Tests

Run the workspace tests with:

```bash
cargo test --workspace
```

The suite covers nested size aggregation, empty directories, symlink safety, size parsing, deterministic rules, JSON serialization, and the compiled CLI process.
