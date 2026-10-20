# SPDX-License-Identifier: AGPL-3.0-only
"""OS-hardened Local File Write-Intent & Recovery Coordinator (Gate G07).

Upgrades over RC1:
1. Implements POSIX directory-descriptor step-by-step path traversal using
   `O_NOFOLLOW | O_CLOEXEC` when `workspace_root` is provided (or on the file
   itself) to block symlink swapping (TOCTOU) and directory escape attacks.
2. Tracks `(st_dev, st_ino, st_mode, byte_length, digest)` in SQLite and checks
   same-volume (`st_dev`) and inode identity before atomic `os.replace`, while
   preserving original file permissions (`st_mode & 0o7777`) on the staged file.
3. Enforces `PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;` for durable
   commits and garbage-collects orphan `.wutong-*.pending` files during recovery.
"""
import errno
import hashlib
import os
import pathlib
import sqlite3
import stat


class SimulatedCrash(RuntimeError):
    pass


class FileConflict(RuntimeError):
    pass


def sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def fsync_dir(path):
    if os.name == "posix":
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _open_regular_nofollow(path: pathlib.Path, workspace_root: pathlib.Path = None):
    """Opens `path` without following symlinks at any intermediate directory component
    (when `workspace_root` is specified on POSIX) or at the target leaf.
    Returns `(data_bytes, stat_result)`.
    """
    p = pathlib.Path(path)
    if os.name == "posix":
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        cloexec = getattr(os, "O_CLOEXEC", 0)
        if workspace_root is not None:
            root = pathlib.Path(workspace_root)
            if root.is_symlink():
                raise FileConflict("ERR_SYMLINK_OR_TRAVERSAL: workspace_root is symlink")
            root_resolved = root.resolve(strict=True)
            try:
                rel = p.relative_to(root) if p.is_absolute() else p
            except ValueError:
                try:
                    rel = p.resolve(strict=False).relative_to(root_resolved)
                except ValueError as e:
                    raise FileConflict("ERR_SYMLINK_OR_TRAVERSAL: path outside workspace_root") from e
            parts = rel.parts
            if not parts or any(part in ("", ".", "..") for part in parts):
                raise FileConflict("ERR_SYMLINK_OR_TRAVERSAL: invalid relative path")
            dir_fd = os.open(str(root_resolved), os.O_RDONLY | nofollow | cloexec)
            try:
                for comp in parts[:-1]:
                    try:
                        lst = os.stat(comp, dir_fd=dir_fd, follow_symlinks=False)
                        if stat.S_ISLNK(lst.st_mode) or not stat.S_ISDIR(lst.st_mode):
                            raise FileConflict(f"ERR_SYMLINK_OR_TRAVERSAL: symlink or non-directory component ({comp})")
                        next_fd = os.open(
                            comp,
                            os.O_RDONLY | nofollow | cloexec | getattr(os, "O_DIRECTORY", 0),
                            dir_fd=dir_fd,
                        )
                        fst = os.fstat(next_fd)
                        if (fst.st_dev, fst.st_ino) != (lst.st_dev, lst.st_ino):
                            os.close(next_fd)
                            raise FileConflict(f"ERR_SYMLINK_OR_TRAVERSAL: directory TOCTOU mismatch ({comp})")
                    except OSError as e:
                        raise FileConflict(f"ERR_SYMLINK_OR_TRAVERSAL: directory component rejected ({comp}): {e}") from e
                    os.close(dir_fd)
                    dir_fd = next_fd
                try:
                    leaf_lst = os.stat(parts[-1], dir_fd=dir_fd, follow_symlinks=False)
                    if stat.S_ISLNK(leaf_lst.st_mode) or not stat.S_ISREG(leaf_lst.st_mode):
                        raise FileConflict("ERR_SYMLINK_OR_TRAVERSAL: leaf symlink or non-regular file")
                    file_fd = os.open(parts[-1], os.O_RDONLY | nofollow | cloexec, dir_fd=dir_fd)
                    leaf_fst = os.fstat(file_fd)
                    if (leaf_fst.st_dev, leaf_fst.st_ino) != (leaf_lst.st_dev, leaf_lst.st_ino):
                        os.close(file_fd)
                        raise FileConflict("ERR_SYMLINK_OR_TRAVERSAL: leaf TOCTOU inode mismatch")
                except OSError as e:
                    raise FileConflict(f"ERR_SYMLINK_OR_TRAVERSAL: leaf open rejected: {e}") from e
                try:
                    st = os.fstat(file_fd)
                    if not stat.S_ISREG(st.st_mode):
                        raise FileConflict("ERR_SYMLINK_OR_TRAVERSAL: not a regular file")
                    chunks = []
                    while True:
                        buf = os.read(file_fd, 65536)
                        if not buf:
                            break
                        chunks.append(buf)
                    return b"".join(chunks), st
                finally:
                    os.close(file_fd)
            finally:
                os.close(dir_fd)
        else:
            # Check every parent component for symlinks and open leaf with O_NOFOLLOW
            cur = p if p.is_absolute() else (pathlib.Path.cwd() / p)
            for parent in [cur, *cur.parents]:
                if parent.is_symlink():
                    raise FileConflict("ERR_SYMLINK_OR_TRAVERSAL: symlink in path")
            try:
                fd = os.open(str(cur), os.O_RDONLY | nofollow | cloexec)
            except OSError as e:
                raise FileConflict(f"ERR_SYMLINK_OR_TRAVERSAL: open failed: {e}") from e
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise FileConflict("ERR_SYMLINK_OR_TRAVERSAL: not regular file")
                chunks = []
                while True:
                    buf = os.read(fd, 65536)
                    if not buf:
                        break
                    chunks.append(buf)
                return b"".join(chunks), st
            finally:
                os.close(fd)
    else:
        if p.is_symlink() or not p.is_file():
            raise FileConflict("ERR_SYMLINK_OR_TRAVERSAL: not regular file")
        st = p.stat()
        return p.read_bytes(), st


class FileCoordinator:
    def __init__(self, db_path, *, workspace_root=None):
        self.workspace_root = (
            pathlib.Path(workspace_root) if workspace_root is not None else None
        )
        self.db = sqlite3.connect(str(db_path), isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=4000")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS docs(
                id TEXT PRIMARY KEY,
                path TEXT UNIQUE NOT NULL,
                digest TEXT NOT NULL,
                dev INTEGER NOT NULL DEFAULT 0,
                ino INTEGER NOT NULL DEFAULT 0,
                mode INTEGER NOT NULL DEFAULT 420
            )"""
        )
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS intents(
                id TEXT PRIMARY KEY,
                oid TEXT NOT NULL,
                old_digest TEXT NOT NULL,
                new_digest TEXT NOT NULL,
                tmp TEXT NOT NULL,
                status TEXT NOT NULL
            )"""
        )
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS revisions(
                intent_id TEXT PRIMARY KEY,
                oid TEXT NOT NULL,
                digest TEXT NOT NULL
            )"""
        )

    def import_file(self, oid, path):
        raw_path = pathlib.Path(path)
        data, st = _open_regular_nofollow(raw_path, self.workspace_root)
        resolved = raw_path.resolve(strict=True)
        self.db.execute(
            "INSERT INTO docs(id, path, digest, dev, ino, mode) VALUES (?,?,?,?,?,?)",
            (
                oid,
                str(resolved),
                sha(data),
                int(st.st_dev),
                int(st.st_ino),
                int(st.st_mode & 0o7777),
            ),
        )

    def replace(self, oid, intent_id, expected, data, crash_at=None):
        row = self.db.execute(
            "SELECT path, digest, dev, ino, mode FROM docs WHERE id=?", (oid,)
        ).fetchone()
        if not row:
            raise FileConflict("unknown object")
        path = pathlib.Path(row[0])
        old, expected_dev, expected_ino, file_mode = row[1], row[2], row[3], row[4]
        disk_bytes, st = _open_regular_nofollow(path, self.workspace_root)
        if old != expected or sha(disk_bytes) != expected:
            raise FileConflict("stale source")
        if expected_dev and st.st_dev != expected_dev:
            raise FileConflict("cross-device swap detected")

        tmp = path.with_name(".wutong-" + intent_id + ".pending")
        if tmp.exists() or tmp.is_symlink():
            raise FileConflict("temp collision")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(str(tmp), flags, file_mode or 0o644)
        try:
            if os.name == "posix" and hasattr(os, "fchmod"):
                os.fchmod(fd, file_mode or 0o644)
            tmp_st = os.fstat(fd)
            if tmp_st.st_dev != st.st_dev:
                raise FileConflict("staging file not on same filesystem device")
            view = memoryview(data)
            written = 0
            while written < len(view):
                n = os.write(fd, view[written:])
                written += n
            os.fsync(fd)
        except Exception:
            os.close(fd)
            tmp.unlink(missing_ok=True)
            raise
        os.close(fd)
        fsync_dir(tmp.parent)

        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute(
                "INSERT INTO intents VALUES (?,?,?,?,?,?)",
                (intent_id, oid, old, sha(data), str(tmp), "prepared"),
            )
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            tmp.unlink(missing_ok=True)
            raise

        if crash_at == "prepared":
            raise SimulatedCrash("after prepared")

        # Re-verify target file identity (inode/device/digest) immediately before atomic replace
        cur_bytes, cur_st = _open_regular_nofollow(path, self.workspace_root)
        if (
            sha(cur_bytes) != expected
            or cur_st.st_dev != st.st_dev
            or (expected_ino and cur_st.st_ino != expected_ino)
        ):
            raise FileConflict("external file modification or inode swap after prepare")

        os.replace(tmp, path)
        fsync_dir(path.parent)
        if crash_at == "replaced":
            raise SimulatedCrash("after replace")
        new_st = path.stat()
        self._finalize(intent_id, oid, sha(data), new_st.st_dev, new_st.st_ino)
        if crash_at == "committed":
            raise SimulatedCrash("after committed")

    def _finalize(self, intent_id, oid, digest, dev=None, ino=None):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if dev is not None and ino is not None:
                self.db.execute(
                    "UPDATE docs SET digest=?, dev=?, ino=? WHERE id=?",
                    (digest, int(dev), int(ino), oid),
                )
            else:
                self.db.execute(
                    "UPDATE docs SET digest=? WHERE id=?", (digest, oid)
                )
            self.db.execute(
                "UPDATE intents SET status='committed' WHERE id=?", (intent_id,)
            )
            self.db.execute(
                "INSERT OR IGNORE INTO revisions VALUES (?,?,?)",
                (intent_id, oid, digest),
            )
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def recover(self):
        result = []
        active_tmps = set()
        rows = self.db.execute(
            "SELECT id,oid,old_digest,new_digest,tmp,status FROM intents WHERE status='prepared'"
        ).fetchall()
        for iid, oid, old, new, tmp_s, status in rows:
            path = pathlib.Path(
                self.db.execute("SELECT path FROM docs WHERE id=?", (oid,)).fetchone()[0]
            )
            tmp = pathlib.Path(tmp_s)
            current = sha(path.read_bytes()) if (path.exists() and not path.is_symlink()) else None
            if current == new:
                st = path.stat()
                self._finalize(iid, oid, new, st.st_dev, st.st_ino)
                tmp.unlink(missing_ok=True)
                result.append((iid, "finalized"))
                continue
            if current == old and tmp.exists() and not tmp.is_symlink() and sha(tmp.read_bytes()) == new:
                os.replace(tmp, path)
                fsync_dir(path.parent)
                st = path.stat()
                self._finalize(iid, oid, new, st.st_dev, st.st_ino)
                result.append((iid, "rolled-forward"))
                continue
            active_tmps.add(str(tmp))
            result.append((iid, "conflict"))

        # Garbage-collect orphan .wutong-*.pending files in tracked parent directories
        for (doc_path_s,) in self.db.execute("SELECT path FROM docs").fetchall():
            parent = pathlib.Path(doc_path_s).parent
            if parent.exists():
                for cand in parent.glob(".wutong-*.pending"):
                    if str(cand) not in active_tmps:
                        cand.unlink(missing_ok=True)
        return result
