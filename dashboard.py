"""
Dashboard — Flask web server serving the real-time Mini IDS dashboard.
"""

from flask import Flask, render_template, jsonify

from alert_manager import AlertManager


def create_app(alert_manager: AlertManager) -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/api/alerts")
    def api_alerts():
        alerts = alert_manager.get_alerts()
        # Return newest first
        return jsonify(list(reversed(alerts)))

    @app.route("/api/stats")
    def api_stats():
        return jsonify(alert_manager.get_stats())

    return app
