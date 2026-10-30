
from flask import Flask, request, jsonify
from pathlib import Path
import sys
import pandas as pd
import io
import logging
from flask import render_template

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR / "ml"))

from pipeline import predict_csv

logging.basicConfig(level=logging.INFO)


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "application": "Cyvanta"
    })


@app.route("/api/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "Please upload a CSV file using the 'file' field."}), 400

    file = request.files["file"]

    if not file.filename or not file.filename.lower().endswith(".csv"):
        return jsonify({"error": "Please upload a CSV file."}), 400

    try:
        # Keep the uploaded file in memory; do not save it to disk.
        content = file.read()

        if not content:
            return jsonify({"error": "The uploaded CSV is empty."}), 400

        result = predict_csv(io.BytesIO(content))

        # Convert non-JSON values (such as NaN) safely.
        results_df = result["results"].replace([float("inf"), float("-inf")], pd.NA)
        results_df = results_df.astype(object).where(pd.notna(results_df), None)

        return jsonify({
            "summary": result["summary"],
            "results": results_df.to_dict(orient="records")
        })

    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    except FileNotFoundError as e:
        app.logger.exception("Model files are missing")
        return jsonify({"error": "Model files are missing. Check ml/models/."}), 500

    except Exception:
        app.logger.exception("Unexpected analysis error")
        return jsonify({"error": "An unexpected error occurred during analysis."}), 500


@app.route("/")
def dashboard():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True, port=5000)

