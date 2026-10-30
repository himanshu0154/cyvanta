import io
import logging
import math
from pathlib import PureWindowsPath

from flask import Flask, jsonify, render_template, request
import numpy as np
import pandas as pd
from werkzeug.exceptions import RequestEntityTooLarge

from ml.pipeline import ModelUnavailableError, load_model, predict_csv
from incident_routes import current_owner, get_store, initialize_investigations
from incident_ai_routes import incident_ai_blueprint

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 300 * 1024 * 1024
logging.basicConfig(level=logging.INFO)


def json_safe(value, *, in_place=False):
    """Ensure even optional uploaded values never serialize as NaN or Infinity."""
    if isinstance(value, dict):
        if in_place:
            for key, item in value.items():
                value[key] = json_safe(item, in_place=True)
            return value
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        if in_place and isinstance(value, list):
            for index, item in enumerate(value):
                value[index] = json_safe(item, in_place=True)
            return value
        return [json_safe(item) for item in value]
    if isinstance(value, np.generic):
        return json_safe(value.item())
    if value is pd.NA or value is pd.NaT:
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "application": "Cyvanta"})


@app.errorhandler(RequestEntityTooLarge)
def file_too_large(_error):
    return jsonify({"error": "The upload exceeds the 300 MB file-size limit."}), 413


@app.route("/api/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "Please upload a CSV file using the 'file' field."}), 400
    file = request.files["file"]
    if not file.filename or not file.filename.lower().endswith(".csv"):
        return jsonify({"error": "Please upload a CSV file."}), 400
    try:
        content = file.read()
        if not content:
            return jsonify({"error": "The uploaded CSV is empty."}), 400
        result = predict_csv(io.BytesIO(content))
        del content
        result["results"] = result["results"].to_dict(orient="records")
        result["dataset_name"] = PureWindowsPath(file.filename.replace("/", "\\")).name
        result["data_source"] = "Uploaded CSV batch"
        # Optional local investigation snapshots never replace model results or
        # make the existing upload depend on AI or storage availability.
        try:
            model, features = load_model()
            imputer = next((step for _name, step in getattr(model, "steps", []) if hasattr(step, "statistics_")), None)
            medians = dict(zip(features, imputer.statistics_)) if imputer is not None else {}
            result["investigation"] = get_store().save_analysis(current_owner(), result, reference_medians=medians)
        except Exception:
            app.logger.error("Optional investigation snapshot could not be saved")
            result["investigation"] = {
                "status": "unavailable", "analysis_id": result["analysis_id"],
                "reason": "Local investigation storage is unavailable or this analysis exceeds its bounded capacity. Existing analysis results remain available.",
            }
        # This response owns its records; avoid cloning hundreds of thousands of
        # dictionaries merely to replace optional non-finite CSV values.
        return jsonify(json_safe(result, in_place=True))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except (ModelUnavailableError, FileNotFoundError):
        app.logger.error("Saved model unavailable or incompatible")
        return jsonify({"error": "The saved analysis model is unavailable or incompatible. Please contact the application operator."}), 503
    except Exception:
        app.logger.error("Unexpected analysis error")
        return jsonify({"error": "An unexpected error occurred during analysis. Please retry."}), 500


@app.route("/")
def dashboard():
    return render_template("index.html")


initialize_investigations(app)
app.register_blueprint(incident_ai_blueprint)


if __name__ == "__main__":
    app.run(port=5000)
