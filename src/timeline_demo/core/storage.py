"""Private local storage primitives; callers must control parent directories."""

import os
import stat
from pathlib import Path


def no_links(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("symlinks are not allowed in private storage paths")
    return path.resolve()


def private_file(path):
    path = no_links(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError("private storage must be a regular file") from None
    else:
        os.close(fd)
    if os.name == "posix":
        path.chmod(0o600)
    return path


def private_tree(root):
    root = no_links(root)
    if os.name == "posix":
        root.chmod(0o700)
        for path in root.rglob("*"):
            no_links(path)
            path.chmod(0o700 if path.is_dir() else 0o600)


def publish_tree(root, target):
    """Flush a private completed tree before exposing it; parents must be trusted."""
    root, target = Path(root), Path(target)
    private_tree(root)
    if os.name == "posix":
        for path in root.rglob("*"):
            if path.is_file():
                with path.open("rb") as stream:
                    os.fsync(stream.fileno())
        for path in [*sorted((p for p in root.rglob("*") if p.is_dir()), reverse=True), root]:
            _sync_dir(path)
    if target.exists():
        raise FileExistsError("publication target already exists")
    root.rename(target)
    if os.name == "posix":
        _sync_dir(target.parent)


def _sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
