"""
Egress-exposure test agent.

Purpose: verify whether an agent deployed on the platform can open an outbound
connection to the public internet. This is a SAFETY TEST, not an exploit:

  - It sends a synthetic marker string (proves connectivity).
  - It sends the NAMES of environment variables present, so you can see the
    attack surface an attacker would target. It NEVER reads or transmits the
    VALUES of any environment variable.

Plug into the agent manager with Start Command: `python main.py`
(Python 3.11, matches the Build Details panel.)

Configure via env var on the agent:
    CANARY_URL   full URL of your receiver, e.g. https://<id>.ngrok-free.app/canary

If CANARY_URL is unset it defaults to the local receiver.
"""
import datetime
import json
import os
import socket
import sys
import urllib.error
import urllib.request

CANARY_URL = os.environ.get("CANARY_URL", "http://127.0.0.1:8000/canary")
TIMEOUT_S = 10

# Env var names that should never even be surfaced as names in a report.
# (Names only are low-risk, but skip the obvious secret-bearing keys to be safe.)
_SENSITIVE_HINTS = ("SECRET", "TOKEN", "PASSWORD", "KEY", "CREDENTIAL", "PRIVATE")


def collect_env_var_names():
    """Return env var NAMES only using os.environ. Values are never read or included.

    Names that look like they hold secrets are masked to their prefix so the
    report shows the attack surface without naming exact secret keys.
    """
    # Using os.environ directly as requested via python -c "import os; print(os.environ)"
    env_data = os.environ
    names = []
    for k in sorted(env_data.keys()):
        upper = k.upper()
        if any(h in upper for h in _SENSITIVE_HINTS):
            names.append(f"{k[:4]}***(masked-secret-name)")
        else:
            names.append(k)
    return names


def build_payload():
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return {
        "marker": f"CANARY-EGRESS-TEST-{ts}",
        "test": "agent-internet-exposure",
        "hostname": socket.gethostname(),
        "note": "synthetic egress probe; env var NAMES only, no values",
        "env_var_names": collect_env_var_names(),
    }


def run_probe():
    payload = build_payload()
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        CANARY_URL,
        data=data,
        headers={"Content-Type": "application/json",
                 "User-Agent": "egress-canary-test/1.0"},
        method="POST",
    )

    print(f"[canary] target   : {CANARY_URL}")
    print(f"[canary] env names: {len(payload['env_var_names'])} (values NOT sent)")

    started = datetime.datetime.now(datetime.timezone.utc)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            elapsed = (datetime.datetime.now(datetime.timezone.utc) - started)
            body = resp.read().decode("utf-8", "replace")
            print(f"[canary] RESULT   : EGRESS ALLOWED  (HTTP {resp.status})")
            print(f"[canary] latency  : {elapsed.total_seconds():.3f}s")
            print(f"[canary] response : {body}")
            print("[canary] VERDICT  : agent CAN reach the public internet.")
            return 0
    except urllib.error.HTTPError as e:
        # Got an HTTP status back -> the request reached the server through the
        # tunnel. Egress WORKED; the non-2xx is a routing/app issue, not a block.
        elapsed = (datetime.datetime.now(datetime.timezone.utc) - started)
        print(f"[canary] RESULT   : EGRESS ALLOWED  (HTTP {e.code} from server)")
        print(f"[canary] latency  : {elapsed.total_seconds():.3f}s")
        print("[canary] VERDICT  : agent CAN reach the public internet "
              f"(server returned {e.code} — check the URL path, e.g. /canary).")
        return 0
    except urllib.error.URLError as e:
        # No HTTP response at all -> connection refused/timeout/DNS. This is the
        # only case that actually indicates egress was blocked or unreachable.
        elapsed = (datetime.datetime.now(datetime.timezone.utc) - started)
        print(f"[canary] RESULT   : EGRESS BLOCKED / FAILED  ({e})")
        print(f"[canary] latency  : {elapsed.total_seconds():.3f}s")
        print("[canary] VERDICT  : outbound connection did not complete "
              "(egress policy working, or receiver unreachable).")
        return 1
    except Exception as e:  # noqa: BLE001
        print(f"[canary] RESULT   : ERROR  ({type(e).__name__}: {e})")
        return 2


if __name__ == "__main__":
    sys.exit(run_probe())