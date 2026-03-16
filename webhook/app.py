import hashlib
import hmac
import logging
import os
import time
from flask import Flask, request, jsonify
from responder import load_k8s_client, respond

# ── Logging setup ────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger(__name__)

# ── App init ─────────────────────────────────────────────────
app = Flask(__name__)

# Shared secret between Falcosidekick and this server.
# Set via environment variable — never hardcoded.
WEBHOOK_SECRET = ""

# In-memory rate limiter: pod_key → last_action_timestamp
# Prevents the same pod being acted on more than once per 5 minutes.
_rate_limit: dict[str, float] = {}
RATE_LIMIT_SECONDS = 300  # 5 minutes

# Kubernetes client — loaded once at startup
try:
    v1 = load_k8s_client()
    K8S_AVAILABLE = True
except Exception as e:
    logger.warning(f"K8s client unavailable (tests/local mode): {e}")
    K8S_AVAILABLE = False
    v1 = None


# ── HMAC verification ────────────────────────────────────────
def verify_signature(payload: bytes, signature: str) -> bool:
    """
    Verify Falcosidekick HMAC-SHA256 signature.
    If no secret is configured, skip verification (dev mode).
    """
    if not WEBHOOK_SECRET:
        return True  # dev mode — no secret set
    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


# ── Rate limiting ────────────────────────────────────────────
def is_rate_limited(pod_name: str, namespace: str) -> bool:
    """Return True if this pod was acted on within the last 5 minutes."""
    key = f"{namespace}/{pod_name}"
    last = _rate_limit.get(key, 0)
    if time.time() - last < RATE_LIMIT_SECONDS:
        logger.info(f"Rate limited: {key} — skipping")
        return True
    _rate_limit[key] = time.time()
    return False


# ── Health endpoint ──────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# ── Main webhook endpoint ─────────────────────────────────────
@app.route("/", methods=["POST"])
def webhook():
    # 1. Verify HMAC signature if secret is configured
    if WEBHOOK_SECRET:
        sig = request.headers.get("X-Signature", "")
        if not verify_signature(request.data, sig):
            logger.warning("Invalid HMAC signature — rejecting request")
            return jsonify({"error": "unauthorized"}), 401

    # 2. Parse JSON payload from Falcosidekick
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "invalid json"}), 400

    # 3. Extract fields
    rule     = payload.get("rule", "")
    priority = payload.get("priority", "")
    fields   = payload.get("output_fields", {})
    pod_name  = fields.get("k8s.pod.name")
    namespace = fields.get("k8s.ns.name")

    logger.info(
        f"Alert received: rule='{rule}' priority={priority} "
        f"pod={pod_name} ns={namespace}"
    )

    # 4. Ignore alerts with no pod metadata (host-level events)
    if not pod_name or not namespace:
        logger.info("No pod metadata — ignoring host-level alert")
        return jsonify({"status": "ignored", "reason": "no pod metadata"}), 200

    # 5. Only act on our custom security rules
    security_keywords = [
        "shell", "sudo", "sensitive", "package manager",
        "binary", "outbound", "root", "netcat", "nmap"
    ]
    rule_lower = rule.lower()
    if not any(kw in rule_lower for kw in security_keywords):
        logger.info(f"Rule '{rule}' not in security ruleset — ignoring")
        return jsonify({"status": "ignored", "reason": "not a security rule"}), 200

    # 6. Rate limiting — prevent acting on same pod repeatedly
    if is_rate_limited(pod_name, namespace):
        return jsonify({"status": "rate_limited"}), 200

    # 7. Act
    if K8S_AVAILABLE and v1:
        respond(v1, pod_name, namespace, priority, rule)
        return jsonify({
            "status": "actioned",
            "pod": pod_name,
            "namespace": namespace,
            "priority": priority,
            "rule": rule
        }), 200
    else:
        logger.warning("K8s unavailable — would have acted on: "
                       f"{pod_name}/{namespace}")
        return jsonify({"status": "k8s_unavailable"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
