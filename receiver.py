"""
Egress canary receiver.

Run this locally. It logs any inbound POST so you can confirm whether a
deployed agent was able to reach it (i.e. whether the platform allows agents
to open outbound connections to the public internet).

Usage:
    pip install flask
    python receiver.py            # binds 127.0.0.1:8000

To give it a public hostname for the egress test, YOU run ngrok yourself:
    ngrok http 8000
and use the https URL ngrok prints as CANARY_URL for the agent.

This receiver only logs. It stores nothing to disk and expects only the
synthetic marker + env-var NAMES payload from the test agent.
"""
import datetime
import json

from flask import Flask, request

app = Flask(__name__)


@app.route("/canary", methods=["POST"])
def canary():
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    src = request.headers.get("X-Forwarded-For", request.remote_addr)
    try:
        body = request.get_json(force=True) or {}
    except Exception:
        body = {"_raw": request.get_data(as_text=True)[:2000]}

    marker = body.get("marker", "<none>")
    env_keys = body.get("env_var_names", [])

    print("=" * 70)
    print(f"[EGRESS HIT] {ts}  from {src}")
    print(f"  marker      : {marker}")
    print(f"  env keys    : {len(env_keys)} names reported")
    if env_keys:
        # Names only — the agent never sends values.
        print(f"  names       : {', '.join(env_keys[:50])}"
              + (" ..." if len(env_keys) > 50 else ""))
    print("=" * 70, flush=True)

    return json.dumps({"status": "received", "server_time": ts}), 200, \
        {"Content-Type": "application/json"}


@app.route("/health", methods=["GET"])
def health():
    return "ok", 200


if __name__ == "__main__":
    # Localhost only. Public exposure is opt-in via your own ngrok tunnel.
    app.run(host="127.0.0.1", port=8000)
