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

EXEC_CLIENT_TIMEOUT = 7200  # exec/commit calls may legitimately run for a long time
PULL_CLIENT_TIMEOUT = 120  # a pull stream that goes silent this long is treated as wedged and retried


def docker_client(timeout: int = EXEC_CLIENT_TIMEOUT) -> Any:
    try:
        import docker  # type: ignore
    except ImportError as err:  # pragma: no cover - dependency is declared
        raise AdapterUnavailable("docker SDK not installed") from err
    try:
        client = docker.from_env(timeout=timeout)
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
        shell: str = "bash -c",  # non-login: a login shell can reset PATH (seen on alpine images)
        platform: str | None = None,
        agent_user: str | None = None,
        pull: bool = True,
        fallback: tuple[str, str | None] | None = None,
    ) -> None:
        self.image = image
        self.workdir = workdir
        self.network_allowed = network_allowed
        self.shell = shell
        self.platform = platform
        self.agent_user = agent_user
        self.fallback = fallback
        self._client = docker_client()  # long timeout: execs and commits
        self._pull_client = docker_client(PULL_CLIENT_TIMEOUT)  # short timeout: detect wedged pulls
        self._env = dict(env or {})
        self._run_kwargs = dict(run_kwargs or {})
        self._run_kwargs.setdefault("network_mode", "bridge" if network_allowed else "none")
        if platform:
            self._run_kwargs["platform"] = platform
        if pull:
            self._ensure_image()  # may adopt the fallback image and platform
        self._container = self._start(self.image)
        self._snapshot_images: list[str] = []

    # -- lifecycle helpers -------------------------------------------------------------
    def _ensure_image(self) -> None:
        """Pull the image unless present. Tries `fallback` when the primary does not exist.

        The docker SDK's `images.pull` swallows errors reported in the pull stream, so the
        low-level streaming API is used and error entries are inspected. Registry rate
        limits (`toomanyrequests`) are waited out; transient errors are retried.
        """
        candidates = [(self.image, self.platform)]
        if self.fallback:
            candidates.append(self.fallback)
        last_error = ""
        for image, platform in candidates:
            if self._image_present(image):
                self._adopt(image, platform)
                return
            status, err = self._pull_with_retries(image, platform)
            if status == "ok":
                self._adopt(image, platform)
                return
            last_error = err
            if status == "not_found":
                _log(f"{image}: not in registry ({err[:80]}); trying fallback" if self.fallback else
                     f"{image}: not in registry ({err[:80]})")
                continue
            raise AdapterUnavailable(f"pull failed for {image}: {err[:300]}")
        raise AdapterUnavailable(f"no image could be pulled: {last_error[:300]}")

    def _adopt(self, image: str, platform: str | None) -> None:
        self.image = image
        self.platform = platform
        if platform:
            self._run_kwargs["platform"] = platform
        else:
            self._run_kwargs.pop("platform", None)

    def _image_present(self, image: str) -> bool:
        import docker  # type: ignore

        try:
            self._client.images.get(image)
            return True
        except docker.errors.ImageNotFound:
            return False

    def _pull_with_retries(self, image: str, platform: str | None) -> tuple[str, str]:
        repo, _, tag = image.rpartition(":")
        if not repo:
            repo, tag = image, "latest"
        waits = [0, 60, 300, 900, 1800, 3600]
        err = ""
        for attempt, wait in enumerate(waits):
            if wait:
                _log(f"waiting {wait}s before retrying {image} ({err[:80]})")
                time.sleep(wait)
            _log(f"pulling {image} ({platform or 'default platform'}) attempt {attempt + 1} ...")
            t0 = time.monotonic()
            err = self._pull_once(repo, tag, platform)
            if not err and self._image_present(image):
                _log(f"pulled {image} in {time.monotonic() - t0:.0f}s")
                return "ok", ""
            low = (err or "image missing after pull").lower()
            if "not found" in low or "manifest unknown" in low or "denied" in low or "unauthorized" in low \
                    or "no such image" in low:
                return "not_found", err or "image missing after pull"
            # toomanyrequests, timeouts, connection resets: retry with backoff
            err = err or "image missing after pull"
        return "error", err

    def _pull_once(self, repo: str, tag: str, platform: str | None) -> str:
        """Stream one pull; return the error text ('' on success)."""
        try:
            stream = self._pull_client.api.pull(repo, tag=tag, stream=True, decode=True, platform=platform)
            for chunk in stream:
                if isinstance(chunk, dict) and ("error" in chunk or "errorDetail" in chunk):
                    detail = chunk.get("errorDetail") or {}
                    return str(chunk.get("error") or detail.get("message") or chunk)
        except Exception as exc:  # noqa: BLE001 - APIError, ReadTimeout, connection errors
            return f"{type(exc).__name__}: {exc}"
        return ""

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
