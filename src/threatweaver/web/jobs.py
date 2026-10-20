"""Background jobs for the dashboard: ingesting a file, and removing one that was uploaded before.

Large files are streamed to a temporary file on disk by the HTTP handler (no memory spike), then
processed here, one at a time, in a worker thread. Each job reports progress (bytes processed of
total) so the page can show a progress bar, and the rest of the dashboard keeps working: the
database is in WAL mode, so readers see the last committed state while the file is being ingested
in a single transaction. The file lands completely or not at all.
"""

from __future__ import annotations

import queue
import shutil
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import store

MAX_QUEUED = 50
KEEP_FINISHED = 20


@dataclass
class Job:
    id: str
    name: str
    size: int
    path: Path | None
    kind: str = "ingest"  # ingest | remove
    source_id: int | None = None  # the source a "remove" job deletes
    state: str = "queued"  # queued | processing | done | error
    bytes_done: int = 0
    result: dict[str, Any] | None = None
    error: str | None = None
    created: float = 0.0
    started: float | None = None
    finished: float | None = None

    def to_dict(self) -> dict[str, Any]:
        now = time.time()
        elapsed = (self.finished or now) - self.started if self.started else 0.0
        pct = 100.0 if self.state == "done" else (100.0 * self.bytes_done / self.size if self.size else 0.0)
        eta = None
        if self.state == "processing" and self.bytes_done > 0 and elapsed > 2:
            eta = max(0.0, elapsed * (self.size - self.bytes_done) / self.bytes_done)
        return {"id": self.id, "name": self.name, "kind": self.kind, "size": self.size, "state": self.state,
                "bytes_done": self.bytes_done, "percent": round(pct, 1), "elapsed": round(elapsed, 1),
                "eta_seconds": None if eta is None else round(eta), "result": self.result, "error": self.error}


class JobManager:
    def __init__(self, db_path: str, work_dir: str | Path | None = None,
                 ingest: Callable[..., Any] = store.ingest_path, remove: Callable[..., Any] = store.remove_source,
                 on_idle: Callable[[], None] | None = None):
        self.db_path = db_path
        self.work_dir = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="threatweaver-uploads-"))
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._ingest = ingest
        self._remove = remove
        self._on_idle = on_idle  # called when a job ends and nothing else is waiting (the dashboard prepares its analysis then)
        self._jobs: dict[str, Job] = {}
        self._order: list[str] = []
        self._queue: queue.Queue[str | None] = queue.Queue()
        self._lock = threading.Lock()
        self._worker: threading.Thread | None = None

    # -- submitting ------------------------------------------------------
    def new_upload_path(self) -> Path:
        return self.work_dir / f"{uuid.uuid4().hex}.upload"

    def submit(self, name: str, path: Path, size: int) -> Job:
        return self._enqueue(Job(uuid.uuid4().hex[:12], name, size, path, created=time.time()))

    def submit_removal(self, source_id: int, name: str) -> Job:
        """Queue the deletion of an uploaded source. It runs on the same worker as ingests, one at a time, and while
        it is queued or running the dashboard refuses other writes. The size is the number of sightings, known once it starts."""
        return self._enqueue(Job(uuid.uuid4().hex[:12], name, 0, None, kind="remove", source_id=source_id, created=time.time()))

    def _enqueue(self, job: Job) -> Job:
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            if self._worker is None:
                self._worker = threading.Thread(target=self._run, name="threatweaver-ingest", daemon=True)
                self._worker.start()
        self._queue.put(job.id)
        return job

    def has_room(self) -> bool:
        with self._lock:
            return sum(1 for j in self._jobs.values() if j.state in ("queued", "processing")) < MAX_QUEUED

    # -- querying --------------------------------------------------------
    def busy(self) -> bool:
        with self._lock:
            return any(j.state in ("queued", "processing") for j in self._jobs.values())

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def listing(self) -> dict[str, Any]:
        with self._lock:
            jobs = [self._jobs[i].to_dict() for i in reversed(self._order)]
        active = [j for j in jobs if j["state"] in ("queued", "processing")]
        finished = [j for j in jobs if j["state"] not in ("queued", "processing")][:KEEP_FINISHED]
        return {"jobs": active[::-1] + finished, "active": len(active)}

    def wait(self, timeout: float = 30.0) -> bool:
        """Block until no job is queued or running (used by tests and shutdown)."""
        end = time.time() + timeout
        while time.time() < end:
            if not self.busy():
                return True
            time.sleep(0.02)
        return False

    # -- worker ----------------------------------------------------------
    def _run(self) -> None:
        while True:
            job_id = self._queue.get()
            if job_id is None:
                return
            job = self._jobs[job_id]
            job.state, job.started = "processing", time.time()
            conn = None
            try:
                conn = store.connect(self.db_path)

                def progress(done: int, total: int, job: Job = job) -> None:
                    job.size, job.bytes_done = total, done

                if job.kind == "remove":
                    gone = self._remove(conn, job.source_id, progress=progress)
                    job.result = {"name": job.name, "removed": True, "sightings": gone.sightings, "indicators": gone.indicators}
                else:
                    res = self._ingest(conn, job.path, source_name=job.name, progress=progress)
                    job.result = {"name": job.name, "already_ingested": res.already_ingested, "candidates": res.candidates,
                                  "new_indicators": res.new_iocs, "sightings": res.new_observations, "rejected": res.rejected}
                job.bytes_done = job.size
                job.state = "done"
            except Exception as exc:  # the page shows the reason; details go to the terminal
                job.error = f"{type(exc).__name__}: {exc}"
                job.state = "error"
            finally:
                job.finished = time.time()
                if conn is not None:
                    conn.close()
                if job.path is not None:
                    try:
                        job.path.unlink()
                    except OSError:
                        pass
                if self._on_idle is not None and self._queue.empty() and job.state == "done":
                    try:
                        self._on_idle()
                    except Exception:  # preparing ahead is a courtesy; it must never break the worker
                        pass

    def close(self) -> None:
        self._queue.put(None)
        shutil.rmtree(self.work_dir, ignore_errors=True)
