# gdusnap

Cached `gdu`-backed disk usage snapshots.

## Install

```bash
python -m pip install -e /inspire/hdd/global_user/guchun-240107140023/modules/gdusnap
```

## Scan

```bash
gdusnap scan /path/to/root --output-dir /path/to/output
```

During a scan, `gdusnap` prints a shallow-scan message, cache hit/miss counts,
and a compact progress bar for the `gdu` rescans that were not satisfied by
cache. Progress rendering uses `rich`, so the label, percentage, bar, count,
known scanned size, and active path are colored in an interactive terminal. The
default cache boundary is `--max-depth 3`.

Progress lines include cached and rescanned boundary directories in the count,
the size known so far, and a shortened active boundary directory. On resume, the
bar starts at the number of cache hits instead of zero:

```text
scan  66.7% ━━━━━━━━━━━━━━━━──────── 2/3 12.00 KiB .../root/new
```

When all max-depth directories are cached, it prints a completed cache-reuse bar.

The output directory receives:

- `summary.html`: browser-viewable report
- `summary.tsv`: sortable table data
- `summary.json`: structured tree data
- `gdu.json`: summary tree that can be opened with `gdu -f`
- `run.json`: parameters and timing for the run

At the end of the run, `gdusnap` prints the total size, duration, cache stats,
output file paths, and the commands below for viewing the result.

## View Results

Open the interactive `gdu` view without rescanning:

```bash
gdu -f /path/to/output/gdu.json
```

Open the HTML report:

```bash
gdusnap serve /path/to/output/summary.html
```

This starts a local HTTP server, automatically chooses a usable port starting at
8000, and prints the URL:

```text
http://localhost:8000/summary.html
```

The command does not call `webbrowser`, so it works on headless servers. Keep
the process running while viewing the report, and stop it with `Ctrl-C`.

Or inspect the sortable text output:

```bash
column -t -s $'\t' /path/to/output/summary.tsv | less -S
```

The shared cache defaults to `$XDG_CACHE_HOME/gdusnap` or `~/.cache/gdusnap`.
Run the same command again to reuse matching cached subtrees.

## Cache Rule

At `--max-depth`, a directory is reused from cache when its direct child names and
child types are unchanged. Existing files with unchanged names are not verified.

To force a full refresh of the max-depth boundary directories:

```bash
gdusnap scan /path/to/root --output-dir /path/to/output --refresh
```
