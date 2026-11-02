"""ETB-15: can the sandbox resolve names and reach the public internet?"""

from __future__ import annotations

from etbh.adapters.base import Sandbox, TaskSpec
from etbh.probes.base import Probe, ProbeResult

DNS_CMD = (
    "python3 -c 'import socket; print(socket.gethostbyname(\"pypi.org\"))' 2>/dev/null "
    "|| getent hosts pypi.org 2>/dev/null || nslookup pypi.org 2>/dev/null"
)
HTTPS_CMD = (
    "curl -sS -I -m 8 -o /dev/null -w '%{http_code}' https://pypi.org/simple/ 2>/dev/null "
    "|| python3 -c 'import urllib.request as u; r=u.urlopen(\"https://pypi.org/simple/\", "
    "timeout=8); print(r.status)'"
)


class NetworkEgress(Probe):
    probe_id = "network_egress"
    etb_class = "ETB-15"
    description = (
        "DNS resolution and an HTTPS HEAD to pypi.org from inside the sandbox. Reachability "
        "only; nothing is downloaded. Open egress lets the agent fetch solutions or fixes."
    )

    def _run(self, task: TaskSpec, sandbox: Sandbox) -> ProbeResult:
        dns = sandbox.exec(DNS_CMD, timeout=20)
        https = sandbox.exec(HTTPS_CMD, timeout=20)
        dns_ok = dns.exit_code == 0 and bool(dns.stdout.strip())
        https_ok = https.exit_code == 0 and https.stdout.strip()[:1] in ("2", "3", "4")
        open_ = dns_ok or https_ok
        ev = ("egress open: " + ", ".join(x for x, ok in (("dns", dns_ok), ("https", https_ok)) if ok)
              if open_ else "no DNS and no HTTPS from the sandbox")
        return self.result(open_, ev, dns=dns_ok, https=https_ok,
                           declared_network_allowed=sandbox.network_allowed)
