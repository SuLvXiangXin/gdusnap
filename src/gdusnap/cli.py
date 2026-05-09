from __future__ import annotations

import argparse
import concurrent.futures
import functools
import hashlib
import html
import http.server
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid

from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table


SCHEMA_VERSION = 1
SIGNATURE_VERSION = 1
OUT_CONSOLE = Console()
ERR_CONSOLE = Console(stderr=True)


@dataclass
class DirNode:
    path: Path
    name: str
    depth: int
    mtime: int
    direct_dsize: int = 0
    direct_asize: int = 0
    subtree_dsize: int = 0
    subtree_asize: int = 0
    direct_child_count: int = 0
    cache_status: str = "shallow"
    children: list["DirNode"] = field(default_factory=list)

    @property
    def total_dsize(self) -> int:
        return (
            self.direct_dsize
            + self.subtree_dsize
            + sum(child.total_dsize for child in self.children)
        )

    @property
    def total_asize(self) -> int:
        return (
            self.direct_asize
            + self.subtree_asize
            + sum(child.total_asize for child in self.children)
        )


@dataclass
class PendingScan:
    node: DirNode
    key: str
    signature: str
    cache_file: Path
    dev: int
    inode: int


@dataclass
class ScanStats:
    dirs_seen: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    gdu_scans: int = 0
    skipped_cross_fs: int = 0


class Cache:
    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.subtrees_dir = cache_dir / "subtrees"
        self.db_path = cache_dir / "manifest.sqlite"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.subtrees_dir.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS subtrees (
                key TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                dev INTEGER NOT NULL,
                inode INTEGER NOT NULL,
                signature TEXT NOT NULL,
                signature_version INTEGER NOT NULL,
                gdu_json TEXT NOT NULL,
                dsize INTEGER NOT NULL,
                asize INTEGER NOT NULL,
                child_count INTEGER NOT NULL,
                scanned_at TEXT NOT NULL,
                gdu_version TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def get(self, key: str, signature: str) -> dict[str, object] | None:
        row = self.conn.execute(
            """
            SELECT gdu_json, dsize, asize, child_count
            FROM subtrees
            WHERE key = ? AND signature = ? AND signature_version = ?
            """,
            (key, signature, SIGNATURE_VERSION),
        ).fetchone()
        if row is None:
            return None
        gdu_json = Path(row[0])
        if not gdu_json.exists():
            return None
        return {
            "gdu_json": gdu_json,
            "dsize": int(row[1]),
            "asize": int(row[2]),
            "child_count": int(row[3]),
        }

    def put(
        self,
        pending: PendingScan,
        dsize: int,
        asize: int,
        child_count: int,
        gdu_version: str,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO subtrees (
                key, path, dev, inode, signature, signature_version,
                gdu_json, dsize, asize, child_count, scanned_at, gdu_version
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                path = excluded.path,
                dev = excluded.dev,
                inode = excluded.inode,
                signature = excluded.signature,
                signature_version = excluded.signature_version,
                gdu_json = excluded.gdu_json,
                dsize = excluded.dsize,
                asize = excluded.asize,
                child_count = excluded.child_count,
                scanned_at = excluded.scanned_at,
                gdu_version = excluded.gdu_version
            """,
            (
                pending.key,
                str(pending.node.path),
                pending.dev,
                pending.inode,
                pending.signature,
                SIGNATURE_VERSION,
                str(pending.cache_file),
                dsize,
                asize,
                child_count,
                datetime.now(timezone.utc).isoformat(),
                gdu_version,
            ),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


class GdusnapHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        ERR_CONSOLE.print("[dim]http[/dim]", format % args)


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        return Path(base) / "gdusnap"
    return Path.home() / ".cache" / "gdusnap"


def disk_size(stat_result: os.stat_result) -> int:
    return int(getattr(stat_result, "st_blocks", 0)) * 512


def human_size(size: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    value = float(size)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{size} B"


def short_path(path: Path, max_parts: int = 3) -> str:
    parts = [part for part in path.parts if part != os.sep]
    if len(parts) <= max_parts:
        return str(path)
    return ".../" + "/".join(parts[-max_parts:])


def active_text(active_scans: list[PendingScan]) -> str | None:
    if not active_scans:
        return None
    first = short_path(active_scans[0].node.path)
    if len(active_scans) == 1:
        return first
    return f"{first} +{len(active_scans) - 1}"


def make_progress() -> Progress:
    return Progress(
        TextColumn("[bold cyan]{task.description}"),
        TextColumn("[bold yellow]{task.percentage:>5.1f}%"),
        BarColumn(
            bar_width=24,
            style="grey37",
            complete_style="green",
            finished_style="bold green",
        ),
        TextColumn("[cyan]{task.completed:.0f}/{task.total:.0f}"),
        TextColumn("[green]{task.fields[size]}"),
        TextColumn("[magenta]{task.fields[current]}"),
        console=ERR_CONSOLE,
        transient=False,
        refresh_per_second=4,
    )


def show_cache_progress(total: int, size: int) -> None:
    if total <= 0:
        return
    with make_progress() as progress:
        task_id = progress.add_task(
            "cache",
            total=total,
            current="",
            size=human_size(size),
        )
        progress.update(task_id, completed=total)
        progress.refresh()


def cache_key(path: Path, stat_result: os.stat_result) -> str:
    text = (
        f"schema={SCHEMA_VERSION}\0"
        f"path={path.resolve()}\0"
        f"dev={stat_result.st_dev}\0"
        f"inode={stat_result.st_ino}"
    )
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()


def entry_type(entry: os.DirEntry[str]) -> str:
    if entry.is_dir(follow_symlinks=False):
        return "dir"
    if entry.is_symlink():
        return "symlink"
    return "file"


def direct_child_signature(path: Path) -> tuple[str, int]:
    items: list[str] = []
    with os.scandir(path) as entries:
        for entry in entries:
            items.append(f"{entry_type(entry)}\t{entry.name}")
    items.sort()
    payload = "\n".join(items)
    signature = hashlib.sha256(
        payload.encode("utf-8", "surrogateescape")
    ).hexdigest()
    return signature, len(items)


def build_tree(
    path: Path,
    depth: int,
    root_dev: int,
    max_depth: int,
    cache: Cache,
    refresh: bool,
    pending: list[PendingScan],
    stats: ScanStats,
    cross_filesystems: bool,
) -> DirNode:
    stat_result = path.stat(follow_symlinks=False)
    name = str(path) if depth == 0 else path.name
    node = DirNode(path=path, name=name, depth=depth, mtime=int(stat_result.st_mtime))
    stats.dirs_seen += 1

    if depth == max_depth:
        signature, child_count = direct_child_signature(path)
        key = cache_key(path, stat_result)
        cache_file = cache.subtrees_dir / f"{key}.gdu.json"
        cached = None if refresh else cache.get(key, signature)
        node.direct_child_count = child_count
        if cached is not None:
            node.subtree_dsize = int(cached["dsize"])
            node.subtree_asize = int(cached["asize"])
            node.cache_status = "cached"
            stats.cache_hits += 1
            return node

        node.cache_status = "pending"
        pending.append(
            PendingScan(
                node=node,
                key=key,
                signature=signature,
                cache_file=cache_file,
                dev=stat_result.st_dev,
                inode=stat_result.st_ino,
            )
        )
        stats.cache_misses += 1
        return node

    child_dirs: list[Path] = []
    with os.scandir(path) as entries:
        for entry in entries:
            child_stat = entry.stat(follow_symlinks=False)
            if entry.is_dir(follow_symlinks=False):
                if not cross_filesystems and child_stat.st_dev != root_dev:
                    stats.skipped_cross_fs += 1
                    continue
                child_dirs.append(Path(entry.path))
                continue
            node.direct_dsize += disk_size(child_stat)
            node.direct_asize += child_stat.st_size

    for child_path in sorted(child_dirs, key=lambda item: item.name):
        node.children.append(
            build_tree(
                path=child_path,
                depth=depth + 1,
                root_dev=root_dev,
                max_depth=max_depth,
                cache=cache,
                refresh=refresh,
                pending=pending,
                stats=stats,
                cross_filesystems=cross_filesystems,
            )
        )
    return node


def gdu_node_size(node: object) -> tuple[int, int]:
    if isinstance(node, dict):
        dsize = int(node.get("dsize", 0))
        asize = int(node.get("asize", dsize))
        return dsize, asize
    if isinstance(node, list):
        dsize = 0
        asize = 0
        for child in node[1:]:
            child_dsize, child_asize = gdu_node_size(child)
            dsize += child_dsize
            asize += child_asize
        return dsize, asize
    return 0, 0


def read_gdu_total(path: Path) -> tuple[int, int]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list) or len(data) < 4:
        raise RuntimeError(f"unexpected gdu JSON format: {path}")
    return gdu_node_size(data[3])


def run_gdu_scan(
    pending: PendingScan,
    gdu_bin: str,
    gdu_cores: int,
    cross_filesystems: bool,
) -> tuple[PendingScan, int, int]:
    tmp_path = pending.cache_file.with_suffix(f".{uuid.uuid4().hex}.tmp")
    command = [
        gdu_bin,
        "-n",
        "-p",
        "-m",
        str(gdu_cores),
        "-o",
        str(tmp_path),
    ]
    if not cross_filesystems:
        command.append("-x")
    command.append(str(pending.node.path))

    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        tmp_path.unlink(missing_ok=True)
        raise RuntimeError(
            f"gdu failed for {pending.node.path}\n"
            f"command: {' '.join(command)}\n"
            f"stderr: {result.stderr.strip()}"
        )

    dsize, asize = read_gdu_total(tmp_path)
    os.replace(tmp_path, pending.cache_file)
    return pending, dsize, asize


def gdu_version(gdu_bin: str) -> str:
    result = subprocess.run(
        [gdu_bin, "--version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    first_line = (result.stdout or result.stderr).splitlines()
    return first_line[0].strip() if first_line else "unknown"


def complete_pending_scans(
    pending_scans: list[PendingScan],
    cache: Cache,
    gdu_bin: str,
    gdu_cores: int,
    jobs: int,
    cross_filesystems: bool,
    stats: ScanStats,
    initial_size: int,
    initial_completed: int,
    total_boundaries: int,
) -> None:
    if not pending_scans:
        return

    version = gdu_version(gdu_bin)
    pending_total = len(pending_scans)
    scanned_size = initial_size
    next_index = 0
    futures: dict[concurrent.futures.Future[tuple[PendingScan, int, int]], PendingScan] = {}

    def submit_next(
        executor: concurrent.futures.ThreadPoolExecutor,
    ) -> None:
        nonlocal next_index
        if next_index >= pending_total:
            return
        pending = pending_scans[next_index]
        next_index += 1
        future = executor.submit(
            run_gdu_scan,
            pending,
            gdu_bin,
            gdu_cores,
            cross_filesystems,
        )
        futures[future] = pending

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
        for _ in range(min(jobs, pending_total)):
            submit_next(executor)

        with make_progress() as progress:
            task_id = progress.add_task(
                "scan",
                total=total_boundaries,
                completed=initial_completed,
                current=active_text(list(futures.values())) or "",
                size=human_size(scanned_size),
            )
            while futures:
                done_futures, _ = concurrent.futures.wait(
                    futures,
                    timeout=1.0,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                if not done_futures:
                    progress.update(
                        task_id,
                        current=active_text(list(futures.values())) or "",
                        size=human_size(scanned_size),
                    )
                    continue

                for future in done_futures:
                    futures.pop(future)
                    pending, dsize, asize = future.result()
                    pending.node.subtree_dsize = dsize
                    pending.node.subtree_asize = asize
                    pending.node.cache_status = "scanned"
                    cache.put(
                        pending=pending,
                        dsize=dsize,
                        asize=asize,
                        child_count=pending.node.direct_child_count,
                        gdu_version=version,
                    )
                    stats.gdu_scans += 1
                    scanned_size += dsize
                    submit_next(executor)

                progress.update(
                    task_id,
                    completed=initial_completed + stats.gdu_scans,
                    current=active_text(list(futures.values())) or "",
                    size=human_size(scanned_size),
                )
            progress.refresh()


def flatten_dirs(root: DirNode) -> list[DirNode]:
    nodes = [root]
    for child in root.children:
        nodes.extend(flatten_dirs(child))
    return nodes


def node_to_dict(node: DirNode) -> dict[str, object]:
    return {
        "path": str(node.path),
        "name": node.name,
        "depth": node.depth,
        "size_bytes": node.total_dsize,
        "apparent_size_bytes": node.total_asize,
        "direct_file_bytes": node.direct_dsize,
        "cache_status": node.cache_status,
        "direct_child_count": node.direct_child_count,
        "children": [node_to_dict(child) for child in node.children],
    }


def gdu_file(name: str, dsize: int, asize: int, mtime: int) -> dict[str, object]:
    item: dict[str, object] = {"name": name, "mtime": mtime}
    if dsize:
        item["dsize"] = dsize
    if asize:
        item["asize"] = asize
    return item


def node_to_gdu(node: DirNode) -> list[object]:
    meta = {"name": str(node.path) if node.depth == 0 else node.name, "mtime": node.mtime}
    children: list[object] = []
    if node.direct_dsize or node.direct_asize:
        children.append(
            gdu_file(
                "__gdusnap_direct_files__",
                node.direct_dsize,
                node.direct_asize,
                node.mtime,
            )
        )
    if node.subtree_dsize or node.subtree_asize:
        children.append(
            gdu_file(
                "__gdusnap_subtree_total__",
                node.subtree_dsize,
                node.subtree_asize,
                node.mtime,
            )
        )
    children.extend(node_to_gdu(child) for child in node.children)
    return [meta, *children]


def write_json(path: Path, payload: object) -> None:
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp_path, path)


def write_tsv(path: Path, root: DirNode) -> None:
    rows = sorted(flatten_dirs(root), key=lambda node: node.total_dsize, reverse=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        handle.write(
            "size_bytes\tsize_human\tapparent_size_bytes\tdepth\t"
            "cache_status\tpath\n"
        )
        for node in rows:
            safe_path = str(node.path).replace("\t", " ")
            handle.write(
                f"{node.total_dsize}\t{human_size(node.total_dsize)}\t"
                f"{node.total_asize}\t{node.depth}\t{node.cache_status}\t"
                f"{safe_path}\n"
            )
    os.replace(tmp_path, path)


def write_gdu_summary(path: Path, root: DirNode) -> None:
    payload = [
        1,
        2,
        {
            "progname": "gdusnap",
            "progver": "0.1.0",
            "timestamp": int(time.time()),
        },
        node_to_gdu(root),
    ]
    write_json(path, payload)


def write_html(path: Path, root: DirNode, run_info: dict[str, object]) -> None:
    rows = sorted(flatten_dirs(root), key=lambda node: node.total_dsize, reverse=True)
    total = max(root.total_dsize, 1)
    body_rows = []
    for node in rows:
        percent = node.total_dsize * 100.0 / total
        body_rows.append(
            "<tr>"
            f"<td class='size'>{html.escape(human_size(node.total_dsize))}</td>"
            f"<td class='bar'><span style='width:{percent:.4f}%'></span></td>"
            f"<td>{node.depth}</td>"
            f"<td>{html.escape(node.cache_status)}</td>"
            f"<td class='path'>{html.escape(str(node.path))}</td>"
            "</tr>"
        )

    generated_at = html.escape(str(run_info["finished_at"]))
    root_path = html.escape(str(root.path))
    html_text = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>gdusnap summary</title>
<style>
body {{
  margin: 0;
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: #202124;
  background: #f6f7f9;
}}
header {{
  padding: 20px 28px;
  background: #ffffff;
  border-bottom: 1px solid #dfe3e8;
}}
h1 {{
  margin: 0 0 8px;
  font-size: 22px;
  font-weight: 650;
}}
.meta {{
  color: #5f6368;
  font-size: 13px;
  line-height: 1.5;
}}
main {{
  padding: 20px 28px 36px;
}}
table {{
  width: 100%;
  border-collapse: collapse;
  background: #ffffff;
  border: 1px solid #dfe3e8;
}}
th, td {{
  padding: 8px 10px;
  border-bottom: 1px solid #edf0f2;
  font-size: 13px;
  text-align: left;
  vertical-align: middle;
}}
th {{
  position: sticky;
  top: 0;
  background: #f0f3f6;
  z-index: 1;
}}
.size {{
  width: 110px;
  white-space: nowrap;
  font-variant-numeric: tabular-nums;
}}
.bar {{
  width: 180px;
}}
.bar span {{
  display: block;
  height: 10px;
  min-width: 1px;
  background: #3b82f6;
  border-radius: 2px;
}}
.path {{
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  overflow-wrap: anywhere;
}}
</style>
</head>
<body>
<header>
  <h1>gdusnap summary</h1>
  <div class="meta">
    Root: {root_path}<br>
    Total: {html.escape(human_size(root.total_dsize))} ({root.total_dsize} bytes)<br>
    Generated: {generated_at}
  </div>
</header>
<main>
  <table>
    <thead>
      <tr>
        <th>Size</th>
        <th>Share</th>
        <th>Depth</th>
        <th>Status</th>
        <th>Path</th>
      </tr>
    </thead>
    <tbody>
      {''.join(body_rows)}
    </tbody>
  </table>
</main>
</body>
</html>
"""
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(html_text, encoding="utf-8")
    os.replace(tmp_path, path)


def print_completion(output_dir: Path, run_info: dict[str, object]) -> None:
    html_path = output_dir / "summary.html"
    tsv_path = output_dir / "summary.tsv"
    json_path = output_dir / "summary.json"
    gdu_path = output_dir / "gdu.json"
    run_path = output_dir / "run.json"
    duration = float(run_info["duration_seconds"])
    OUT_CONSOLE.print("[bold green]gdusnap complete[/bold green]")
    table = Table.grid(padding=(0, 1))
    table.add_column(style="bold cyan", justify="right")
    table.add_column(style="white")
    table.add_row("root", str(run_info["root"]))
    table.add_row(
        "total",
        f"{run_info['total_size_human']} ({run_info['total_size_bytes']} bytes)",
    )
    table.add_row("duration", f"{duration:.2f}s")
    table.add_row(
        "cache",
        (
            f"hits={run_info['cache_hits']} "
            f"misses={run_info['cache_misses']} "
            f"gdu_scans={run_info['gdu_scans']}"
        ),
    )
    table.add_row("html", str(html_path))
    table.add_row("tsv", str(tsv_path))
    table.add_row("json", str(json_path))
    table.add_row("gdu", str(gdu_path))
    table.add_row("run", str(run_path))
    table.add_row("view gdu", f"gdu -f {gdu_path}")
    table.add_row("view html", f"gdusnap serve {html_path}")
    OUT_CONSOLE.print(table)


def log_scan_start(root: Path) -> None:
    ERR_CONSOLE.print("[bold blue]gdusnap[/bold blue] shallow scan", root)


def log_cache_stats(cache_hits: int, cache_misses: int) -> None:
    ERR_CONSOLE.print(
        "[bold blue]gdusnap[/bold blue] cache",
        f"hits={cache_hits}",
        f"misses={cache_misses}",
    )


def log_outputs(output_dir: Path, total_size: int, duration: float) -> None:
    ERR_CONSOLE.print("[bold blue]gdusnap[/bold blue] wrote", output_dir)
    ERR_CONSOLE.print(
        "[bold blue]gdusnap[/bold blue] total",
        human_size(total_size),
        f"duration={duration:.2f}s",
    )


def scan(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    cache_dir = Path(args.cache_dir).expanduser().resolve()

    if not root.is_dir():
        raise RuntimeError(f"root is not a directory: {root}")
    if args.max_depth < 0:
        raise RuntimeError("--max-depth must be >= 0")
    if args.jobs < 1:
        raise RuntimeError("--jobs must be >= 1")
    if args.gdu_cores < 1:
        raise RuntimeError("--gdu-cores must be >= 1")

    gdu_bin = shutil.which(args.gdu_bin)
    if gdu_bin is None:
        raise RuntimeError(f"gdu binary not found: {args.gdu_bin}")

    output_dir.mkdir(parents=True, exist_ok=True)
    started = time.time()
    started_at = datetime.now(timezone.utc).isoformat()
    stats = ScanStats()
    pending: list[PendingScan] = []
    cache = Cache(cache_dir)

    log_scan_start(root)
    try:
        root_stat = root.stat(follow_symlinks=False)
        tree = build_tree(
            path=root,
            depth=0,
            root_dev=root_stat.st_dev,
            max_depth=args.max_depth,
            cache=cache,
            refresh=args.refresh,
            pending=pending,
            stats=stats,
            cross_filesystems=args.cross_filesystems,
        )
        log_cache_stats(stats.cache_hits, len(pending))
        boundary_total = stats.cache_hits + len(pending)
        if boundary_total and not pending:
            show_cache_progress(boundary_total, tree.total_dsize)
        complete_pending_scans(
            pending_scans=pending,
            cache=cache,
            gdu_bin=gdu_bin,
            gdu_cores=args.gdu_cores,
            jobs=args.jobs,
            cross_filesystems=args.cross_filesystems,
            stats=stats,
            initial_size=tree.total_dsize,
            initial_completed=stats.cache_hits,
            total_boundaries=boundary_total,
        )
    finally:
        cache.close()

    finished_at = datetime.now(timezone.utc).isoformat()
    duration = time.time() - started
    run_info: dict[str, object] = {
        "root": str(root),
        "max_depth": args.max_depth,
        "output_dir": str(output_dir),
        "cache_dir": str(cache_dir),
        "refresh": args.refresh,
        "cross_filesystems": args.cross_filesystems,
        "gdu_bin": gdu_bin,
        "gdu_cores": args.gdu_cores,
        "jobs": args.jobs,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": duration,
        "dirs_seen": stats.dirs_seen,
        "cache_hits": stats.cache_hits,
        "cache_misses": stats.cache_misses,
        "gdu_scans": stats.gdu_scans,
        "skipped_cross_filesystems": stats.skipped_cross_fs,
        "total_size_bytes": tree.total_dsize,
        "total_size_human": human_size(tree.total_dsize),
    }

    summary_payload = {
        **run_info,
        "tree": node_to_dict(tree),
    }
    write_json(output_dir / "summary.json", summary_payload)
    write_json(output_dir / "run.json", run_info)
    write_tsv(output_dir / "summary.tsv", tree)
    write_gdu_summary(output_dir / "gdu.json", tree)
    write_html(output_dir / "summary.html", tree, run_info)

    log_outputs(output_dir, tree.total_dsize, duration)
    print_completion(output_dir, run_info)
    return 0


def serve(args: argparse.Namespace) -> int:
    html_path = Path(args.html).expanduser().resolve()
    if not html_path.is_file():
        raise RuntimeError(f"html file does not exist: {html_path}")
    if args.port < 1 or args.port > 65535:
        raise RuntimeError("--port must be between 1 and 65535")
    if args.port_tries < 1:
        raise RuntimeError("--port-tries must be >= 1")

    directory = html_path.parent
    handler = functools.partial(
        GdusnapHTTPRequestHandler,
        directory=str(directory),
    )
    server = None
    last_error: OSError | None = None
    last_port = min(65535, args.port + args.port_tries - 1)
    for port in range(args.port, last_port + 1):
        try:
            server = http.server.ThreadingHTTPServer((args.host, port), handler)
            break
        except OSError as exc:
            last_error = exc

    if server is None:
        raise RuntimeError(
            f"could not bind {args.host}:{args.port}-"
            f"{last_port}: {last_error}"
        )

    host_for_url = "localhost" if args.host in {"127.0.0.1", "0.0.0.0"} else args.host
    url = f"http://{host_for_url}:{server.server_port}/{html_path.name}"
    OUT_CONSOLE.print("[bold green]gdusnap serve[/bold green]")
    table = Table.grid(padding=(0, 1))
    table.add_column(style="bold cyan", justify="right")
    table.add_column(style="white")
    table.add_row("file", str(html_path))
    table.add_row("root", str(directory))
    table.add_row("url", url)
    table.add_row("stop", "Ctrl-C")
    OUT_CONSOLE.print(table)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        OUT_CONSOLE.print("\n[bold yellow]gdusnap serve stopped[/bold yellow]")
    finally:
        server.server_close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gdusnap",
        description="Cached gdu-backed disk usage snapshots.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan a directory")
    scan_parser.add_argument("root", help="directory to scan")
    scan_parser.add_argument(
        "--output-dir",
        required=True,
        help="directory where summary.html, summary.tsv, summary.json, gdu.json, and run.json are written",
    )
    scan_parser.add_argument(
        "--max-depth",
        type=int,
        default=3,
        help="cache boundary depth, default: 3",
    )
    scan_parser.add_argument(
        "--cache-dir",
        default=str(default_cache_dir()),
        help="shared cache directory, default: $XDG_CACHE_HOME/gdusnap or ~/.cache/gdusnap",
    )
    scan_parser.add_argument(
        "--refresh",
        action="store_true",
        help="ignore matching cache entries and rescan boundary directories",
    )
    scan_parser.add_argument(
        "--cross-filesystems",
        action="store_true",
        help="allow crossing filesystem boundaries below root",
    )
    scan_parser.add_argument(
        "--gdu-bin",
        default="gdu",
        help="gdu executable name or path, default: gdu",
    )
    scan_parser.add_argument(
        "--gdu-cores",
        type=int,
        default=8,
        help="cores passed to each gdu process, default: 8",
    )
    scan_parser.add_argument(
        "--jobs",
        type=int,
        default=4,
        help="number of concurrent gdu processes for cache misses, default: 4",
    )
    scan_parser.set_defaults(func=scan)

    serve_parser = subparsers.add_parser(
        "serve",
        help="serve a generated HTML report and print a localhost URL",
    )
    serve_parser.add_argument("html", help="HTML file to serve, usually summary.html")
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="host interface to bind, default: 127.0.0.1",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="first port to try, default: 8000",
    )
    serve_parser.add_argument(
        "--port-tries",
        type=int,
        default=100,
        help="number of consecutive ports to try, default: 100",
    )
    serve_parser.set_defaults(func=serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        ERR_CONSOLE.print("[bold yellow]gdusnap interrupted[/bold yellow]")
        return 130
    except Exception as exc:
        ERR_CONSOLE.print("[bold red]gdusnap error:[/bold red]", str(exc))
        return 1
