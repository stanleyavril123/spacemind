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

SpaceMind opens a centered interactive folder selector. Use the arrow keys or `j`/`k` to
move, `Enter` to scan, `c` to enter a custom path, and `q` to quit. The default choice is
your current folder, with quick choices for Home, Downloads, Documents, and Desktop when
available.

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

## Run without installing

For development, the equivalent command is:

```bash
cargo run --release --
```
