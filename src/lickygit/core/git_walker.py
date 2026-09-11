"""Git repository walker using GitPython — cross-platform."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from git import Repo, InvalidGitRepositoryError, GitCommandNotFound


# Default maximum file size to scan (5 MB). Files larger than this are skipped to prevent OOM.
DEFAULT_MAX_FILE_SIZE: int = 5 * 1024 * 1024


def safe_rmtree(target_dir: str | Path) -> None:
    """Recursively remove a directory, handling Windows read-only git files."""
    p = Path(target_dir)
    if not p.exists():
        return

    def _handle_readonly(func: Any, path: str, exc: Any) -> None:
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except Exception:
            pass

    if sys.version_info >= (3, 12):
        shutil.rmtree(p, onexc=_handle_readonly)
    else:
        shutil.rmtree(p, onerror=_handle_readonly)


class GitWalkerError(Exception):
    """Raised when a git operation fails."""


class GitWalker:
    """Walk Git revisions and extract file contents.

    Uses GitPython for cross-platform support (Windows/macOS/Linux).
    Never calls ``os.chdir`` — all operations use explicit paths.
    """

    def __init__(
        self,
        repo_path: str | Path,
        head_only: bool = False,
        staged: bool = False,
        since_commit: str | None = None,
        diff_base: str | None = None,
    ) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.head_only = head_only
        self.staged = staged
        self.since_commit = since_commit
        self.diff_base = diff_base
        try:
            self.repo = Repo(self.repo_path)
        except InvalidGitRepositoryError as exc:
            raise GitWalkerError(f"Not a git repository: {self.repo_path}") from exc
        except GitCommandNotFound as exc:
            raise GitWalkerError(
                "Git is not installed or not on PATH."
            ) from exc

    # ------------------------------------------------------------------
    # Revision listing
    # ------------------------------------------------------------------

    def get_revisions(self) -> list[str]:
        """Return commit SHAs to scan.

        If *staged* is ``True``, returns a sentinel ``["STAGED"]``.
        If *head_only* is ``True``, returns only ``HEAD``.
        If *diff_base* is set, returns commits in ``diff_base..HEAD``.
        If *since_commit* is set, returns commits in ``since_commit..HEAD``.
        Otherwise returns **all** reachable commits.
        """
        if self.staged:
            return ["STAGED"]

        if self.head_only:
            try:
                return [self.repo.head.commit.hexsha]
            except Exception:
                return []

        # Diff-aware PR scanning: only commits in the range
        if self.diff_base:
            try:
                return [c.hexsha for c in self.repo.iter_commits(f"{self.diff_base}..HEAD")]
            except Exception:
                return []

        # Incremental scanning: only new commits since a point
        if self.since_commit:
            try:
                return [c.hexsha for c in self.repo.iter_commits(f"{self.since_commit}..HEAD")]
            except Exception:
                return []

        return [c.hexsha for c in self.repo.iter_commits("--all")]

    # ------------------------------------------------------------------
    # File iteration
    # ------------------------------------------------------------------

    def get_file_contents(
        self,
        commit_sha: str,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    ) -> Iterator[tuple[str, str, str]]:
        """Yield ``(file_path, text_content, blob_sha)`` for non-binary files.

        Files larger than *max_file_size* or containing null bytes are skipped.
        """
        # 1. Staged files from Git index (pre-commit)
        if commit_sha == "STAGED" or self.staged:
            # If HEAD exists, only inspect files with staged additions/modifications
            staged_paths: set[str] | None = None
            try:
                # Compare index against HEAD to find what's actually staged
                diffs = self.repo.index.diff("HEAD")
                staged_paths = {
                    d.b_path or d.a_path
                    for d in diffs
                    if d.change_type in ("A", "M", "R", "C") and (d.b_path or d.a_path)
                }
            except Exception:
                # Initial commit (no HEAD yet): scan all staged entries
                staged_paths = None

            for (path, stage), entry in self.repo.index.entries.items():
                if stage != 0:
                    continue
                path_str = str(path)
                if staged_paths is not None and path_str not in staged_paths:
                    continue
                try:
                    stream = self.repo.odb.stream(entry.binsha)
                    if hasattr(stream, "size") and stream.size > max_file_size:
                        continue
                    data: bytes = stream.read()
                    if len(data) > max_file_size or b"\x00" in data[:8192]:
                        continue
                    text = data.decode("utf-8", errors="replace")
                    yield (path_str, text, entry.hexsha)
                except Exception:
                    continue
            return

        # 2. Historical commit files
        commit = self.repo.commit(commit_sha)
        for blob in commit.tree.traverse():
            if blob.type != "blob":  # type: ignore[attr-defined]
                continue
            try:
                # Guard against huge files (e.g. database dumps, big datasets)
                if blob.size > max_file_size:  # type: ignore[attr-defined]
                    continue
                data: bytes = blob.data_stream.read()  # type: ignore[attr-defined]
                if b"\x00" in data[:8192]:
                    continue  # binary
                text = data.decode("utf-8", errors="replace")
                yield (blob.path, text, blob.hexsha)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                continue  # unreadable — skip

    # ------------------------------------------------------------------
    # Commit metadata
    # ------------------------------------------------------------------

    def get_commit_info(self, sha: str) -> dict[str, str]:
        """Return author, date and message for the given commit."""
        if sha == "STAGED":
            return {
                "author": "Current User (Staged)",
                "date": "Working Tree",
                "message": "Staged changes for upcoming commit",
            }

        commit = self.repo.commit(sha)
        return {
            "author": str(commit.author),
            "date": commit.committed_datetime.isoformat(),
            "message": commit.message.strip(),
        }

    # ------------------------------------------------------------------
    # Clone helper
    # ------------------------------------------------------------------

    @classmethod
    def clone(
        cls,
        url: str,
        target_dir: str | Path | None = None,
    ) -> GitWalker:
        """Clone a remote repository and return a :class:`GitWalker` for it.

        Parameters
        ----------
        url:
            Any URL that ``git clone`` accepts.
        target_dir:
            Where to clone. If *None* a temporary directory is created.
        """
        if target_dir is None:
            target_dir = Path(tempfile.mkdtemp(prefix="lickygit_"))
        else:
            target_dir = Path(target_dir)

        try:
            subprocess.run(
                ["git", "clone", "--", url, str(target_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            raise GitWalkerError(f"Failed to clone {url}: {exc.stderr}") from exc

        return cls(target_dir)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def delete_repo(self) -> None:
        """Remove the repository directory from disk safely on all platforms."""
        safe_rmtree(self.repo_path)
