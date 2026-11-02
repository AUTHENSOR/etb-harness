"""Docker-backed sandbox. Never starts the daemon; reports absence and lets callers skip.

Disk note: SWE-bench images are several GB each. `DockerSandbox.close()` removes the
container and every snapshot image it created; the runner additionally calls
`prune_image()` after each task when `--prune` is set so images do not accumulate on the
internal disk (idle data belongs on the USB drives).

User model: the container runs as root (benchmark images assume it). When `agent_user` is
set, every exec/read/write made through the Sandbox protocol runs as that user, which is
how the `after` profile's `agent_unprivileged` switch is realised; the adapter grades with
`exec_as(..., "root")` and `write_file_as_root`.
"""

from __future__ import annotations

import base64
import shlex
import sys
import time
from typing import Any

from etbh.adapters.base import AdapterUnavailable, ExecResult


def docker_client() -> Any:
    try:
        import docker  # type: ignore
    except ImportError as err:  # pragma: no cover - dependency is declared
        raise AdapterUnavailable("docker SDK not installed") from err
    try:
        client = docker.from_env()
        client.ping()
    except Exception as err:  # docker.errors.DockerException and socket errors
        raise AdapterUnavailable(
            "Docker daemon not reachable (Docker Desktop is installed but not running). "
            "Start it manually; the harness never starts it."
        ) from err
    return client


def docker_available() -> bool:
    try:
        docker_client()
    except AdapterUnavailable:
        return False
    return True


def _log(msg: str) -> None:
    print(f"[etbh] {msg}", file=sys.stderr, flush=True)


class DockerSandbox:
    def __init__(
        self,
        image: str,
        *,
        workdir: str = "/testbed",
        network_allowed: bool = True,
        run_kwargs: dict[str, Any] | None = None,
        env: dict[str, str] | None = None,
        shell: str = "bash -lc",
        platform: str | None = None,
        agent_user: str | None = None,
        pull: bool = True,
    ) -> None:
        self.image = image
        self.workdir = workdir
        self.network_allowed = network_allowed
        self.shell = shell
        self.platform = platform
        self.agent_user = agent_user
        self._client = docker_client()
        self._env = dict(env or {})
        self._run_kwargs = dict(run_kwargs or {})
        self._run_kwargs.setdefault("network_mode", "bridge" if network_allowed else "none")
        if platform:
            self._run_kwargs["platform"] = platform
        if pull:
            self._ensure_image()
        self._container = self._start(image)
        self._snapshot_images: list[str] = []

    # -- lifecycle helpers -------------------------------------------------------------
    def _ensure_image(self) -> None:
        import docker  # type: ignore

        try:
            self._client.images.get(self.image)
            return
        except docker.errors.ImageNotFound:
            pass
        repo, _, tag = self.image.rpartition(":")
        if not repo:
            repo, tag = self.image, "latest"
        _log(f"pulling {self.image} ({self.platform or 'default platform'}) ...")
        t0 = time.monotonic()
        self._client.images.pull(repo, tag=tag, platform=self.platform)
        _log(f"pulled {self.image} in {time.monotonic() - t0:.0f}s")

    def _start(self, image: str) -> Any:
        return self._client.containers.run(
            image, command="sleep infinity", detach=True, working_dir=self.workdir,
            environment=self._env, **self._run_kwargs,
        )

    # -- Sandbox protocol -----------------------------------------------------------
    def exec(self, cmd: str, timeout: float = 600) -> ExecResult:
        return self.exec_as(cmd, self.agent_user, timeout)

    def exec_as(self, cmd: str, user: str | None, timeout: float = 600) -> ExecResult:
        wrapped = f"timeout {int(timeout)} {self.shell} {shlex.quote(cmd)}"
        kwargs: dict[str, Any] = {"demux": True}
        if user:
            kwargs["user"] = user
        code, (out, err) = self._container.exec_run(wrapped, **kwargs)
        stdout = (out or b"").decode(errors="replace")
        stderr = (err or b"").decode(errors="replace")
        return ExecResult(exit_code=code, stdout=stdout, stderr=stderr, timed_out=(code == 124))

    def read_file(self, path: str) -> str:
        res = self.exec(f"cat {shlex.quote(path)}", timeout=60)
        if res.exit_code != 0:
            raise FileNotFoundError(f"{path}: {res.stderr.strip()}")
        return res.stdout

    def write_file(self, path: str, content: str) -> None:
        """Write as the agent user (so permission hardening is actually exercised)."""
        self._write(path, content, self.agent_user)

    def write_file_as_root(self, path: str, content: str) -> None:
        self._write(path, content, None)

    def _write(self, path: str, content: str, user: str | None) -> None:
        directory = path.rpartition("/")[0] or "/"
        payload = base64.b64encode(content.encode()).decode()
        cmd = (f"mkdir -p {shlex.quote(directory)} && printf %s {shlex.quote(payload)} | "
               f"base64 -d > {shlex.quote(path)}")
        res = self.exec_as(cmd, user, timeout=120)
        if res.exit_code != 0:
            raise PermissionError(f"write failed: {path}: {res.stderr.strip()[:200]}")

    def path_exists(self, path: str) -> bool:
        return self.exec(f"test -e {shlex.quote(path)}", timeout=30).exit_code == 0

    def list_dir(self, path: str) -> list[str]:
        res = self.exec(f"ls -1A {shlex.quote(path)}", timeout=30)
        return [ln for ln in res.stdout.splitlines() if ln] if res.exit_code == 0 else []

    def snapshot(self) -> str:
        image = self._container.commit()
        self._snapshot_images.append(image.id)
        return image.id

    def restore(self, token: str) -> None:
        old = self._container
        self._container = self._start(token)
        old.remove(force=True)

    # -- lifecycle ----------------------------------------------------------------------
    def close(self) -> None:
        try:
            self._container.remove(force=True)
        finally:
            for img in self._snapshot_images:
                try:
                    self._client.images.remove(img, force=True)
                except Exception:  # noqa: BLE001 - best-effort cleanup
                    pass
            self._snapshot_images.clear()

    def prune_image(self) -> None:
        """Remove the task image itself (call after the last use of a task)."""
        try:
            self._client.images.remove(self.image, force=True)
            _log(f"pruned {self.image}")
        except Exception:  # noqa: BLE001 - best-effort cleanup
            pass

    def __enter__(self) -> DockerSandbox:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
