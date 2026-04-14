import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from vt_api import VTAPI

# ── Load environment variables from .env securely ────────────────────────────
load_dotenv()

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests from the frontend

vt_client = VTAPI()

@app.route("/check", methods=["POST"])
def check_url():
    """
    POST /check
    Body: { "url": "https://example.com" }

    Response: {
        "status": "safe | suspicious | malicious",
        "stats": { "malicious": N, "suspicious": N, "harmless": N, "undetected": N },
        "heuristic": { "score": N, "status": "...", "reasons": [...] },
        "vt_error": null | "string"
    }
    """
    data = request.get_json(silent=True)

    if not data or "url" not in data:
        return jsonify({"error": "Invalid request. 'url' field is required."}), 400

    url = data["url"].strip()

    # ── Input validation ──────────────────────────────────────────────────────
    if not url.startswith("http://") and not url.startswith("https://"):
        return jsonify({"error": "Invalid URL. Must start with http:// or https://"}), 400

    if len(url) > 2048:
        return jsonify({"error": "URL exceeds maximum allowed length."}), 400

    try:
        result = vt_client.check_url(url)
        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
