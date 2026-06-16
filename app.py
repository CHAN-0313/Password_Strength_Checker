"""
CyberShield - Advanced Password Security Analyzer
Flask Backend Application
"""

from flask import Flask, render_template, request, jsonify
from utils.analyzer import analyze_password, generate_strong_password

app = Flask(__name__)
app.secret_key = "cybershield-secret-2024"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    POST /api/analyze
    Body: { "password": "..." }
    Returns: full analysis JSON
    """
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not isinstance(password, str):
        return jsonify({"error": "Invalid input"}), 400

    result = analyze_password(password)
    return jsonify(result)


@app.route("/api/generate", methods=["GET"])
def generate():
    """
    GET /api/generate?length=20
    Returns: { "password": "...", "analysis": {...} }
    """
    try:
        length = int(request.args.get("length", 20))
        length = max(12, min(64, length))   # clamp 12-64
    except ValueError:
        length = 20

    password = generate_strong_password(length)
    analysis = analyze_password(password)
    return jsonify({"password": password, "analysis": analysis})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)