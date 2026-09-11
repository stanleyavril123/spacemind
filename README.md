# SpaceMind

SpaceMind is a privacy-first storage assistant for Windows and Linux. It scans locally,
explains what is using space, and suggests items worth reviewing. It never deletes files
automatically.

## Install the command

From the repository, install the SpaceMind CLI once:

```bash
cargo install --path apps/cli --locked
```

After that, start it from any directory with:

```bash
spacemind
```

SpaceMind opens a centered home menu where you can scan storage, review scan history, or
quit. Use the arrow keys or `j`/`k` to move and `Enter` to select. The scan flow then lets
you choose the current folder, Home, Downloads, Documents, Desktop, or a custom path.

You can also skip the selector and provide a folder directly:

```bash
spacemind scan ~/Downloads
```

Keep sensitive folders in storage totals while preventing cleanup recommendations:

```bash
spacemind scan ~ --protect ~/Documents
```

Skip paths entirely with `--ignore`. Both flags can be repeated and accept quoted
`*`, `?`, and `**` wildcard patterns:

```bash
spacemind scan ~ --ignore "**/.git/**" --ignore "node_modules"
```

During the scan, SpaceMind reports progress for filesystem scanning, duplicate hashing,
relationship detection, and recommendation building. Press `Ctrl+C` to cancel safely. The analysis is read-only;
no files are moved, deleted, or uploaded.

For machine-readable output:

```bash
spacemind scan ~/Downloads --format json
```

Progress is written only to an interactive terminal on stderr, so JSON on stdout remains valid.
The interface adapts to the terminal width and uses a restrained orange, charcoal, and gray
palette. Set `NO_COLOR=1` or pipe the output to another command to receive plain text without
ANSI color codes.

## Scan history

Successful scans are saved automatically to a local SQLite database. SpaceMind stores
filesystem metadata and analysis results, never file contents. Choose **Scan history**
from the home menu. The equivalent command for scripts is:

```bash
spacemind history
```

Use `spacemind history --format json` for structured history output. Run a private,
one-off scan without saving it with `--no-history`:

```bash
spacemind scan ~/Downloads --no-history
```

The database defaults to the platform user-data directory. Override it for development,
portable use, or testing with `--database ./spacemind.db` or the
`SPACEMIND_DATABASE` environment variable.

## Run without installing

For development, the equivalent command is:

```bash
cargo run --release --
```
