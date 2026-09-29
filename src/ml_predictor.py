"""
ML Predictor — loads a trained model and predicts whether a URL is phishing.
Output is advisory only; final verdict comes from the risk engine.
"""

import os
import json
import joblib
import numpy as np

# Project paths
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")

# Lazy-loaded model state
_model = None
_scaler = None
_feature_names = None
_model_name = None
_evaluation_summary = None


def _load_model(model_name: str = None):
    """Load model, scaler, and feature names."""
    global _model, _scaler, _feature_names, _model_name, _evaluation_summary

    # Load evaluation summary to find best model
    summary_path = os.path.join(MODELS_DIR, "evaluation_summary.json")
    if os.path.exists(summary_path):
        with open(summary_path) as f:
            _evaluation_summary = json.load(f)

    if model_name is None:
        # Use configured model or best from evaluation
        from dotenv import load_dotenv
        load_dotenv()
        model_name = os.getenv("ML_MODEL")
        if not model_name and _evaluation_summary:
            model_name = _evaluation_summary.get("best_model", "random_forest")
        if not model_name:
            model_name = "random_forest"

    model_path = os.path.join(MODELS_DIR, f"{model_name}_model.joblib")
    scaler_path = os.path.join(MODELS_DIR, "scaler.joblib")
    feature_names_path = os.path.join(MODELS_DIR, "feature_names.json")

    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Model not found: {model_path}. Run 'python src/train_model.py' first."
        )

    _model = joblib.load(model_path)
    _model_name = model_name

    if os.path.exists(scaler_path):
        _scaler = joblib.load(scaler_path)

    if os.path.exists(feature_names_path):
        with open(feature_names_path) as f:
            _feature_names = json.load(f)


def predict_url(url: str, model_name: str = None) -> dict:
    """
    Predict whether a URL is phishing or legitimate.

    Args:
        url: The URL to classify.
        model_name: Specific model to use (optional).

    Returns:
        Dict with prediction, probability, model name, and feature importances.
        The probability is the model's output, not absolute certainty.
    """
    global _model, _model_name

    if _model is None or (model_name and model_name != _model_name):
        _load_model(model_name)

    # Import here to avoid circular import at module level
    from url_features import extract_features

    features = extract_features(url)
    feature_vector = _build_feature_vector(features)

    # Scale for logistic regression
    if _model_name == "logistic_regression" and _scaler is not None:
        feature_vector = _scaler.transform([feature_vector])
    else:
        feature_vector = np.array([feature_vector])

    prediction = _model.predict(feature_vector)[0]
    probability = _model.predict_proba(feature_vector)[0]

    result = {
        "url": url,
        "prediction": "phishing" if prediction == 1 else "legitimate",
        "probability": round(float(probability[1]), 4),  # phishing probability
        "confidence": round(float(max(probability)), 4),
        "model": _model_name,
        "features": features,
        "note": "This is the model's estimated probability, not absolute certainty.",
    }

    # Add model metrics if available
    if _evaluation_summary and _model_name in _evaluation_summary.get("models", {}):
        result["model_metrics"] = _evaluation_summary["models"][_model_name]

    return result


def predict_urls(urls: list, model_name: str = None) -> list:
    """
    Predict multiple URLs at once.

    Args:
        urls: List of URL strings.
        model_name: Specific model to use.

    Returns:
        List of prediction dicts.
    """
    return [predict_url(url, model_name) for url in urls]


def get_available_models() -> list:
    """List available trained models."""
    models = []
    if os.path.exists(MODELS_DIR):
        for f in os.listdir(MODELS_DIR):
            if f.endswith("_model.joblib"):
                name = f.replace("_model.joblib", "")
                models.append(name)
    return models


def get_evaluation_summary() -> dict:
    """Return the evaluation summary from training."""
    summary_path = os.path.join(MODELS_DIR, "evaluation_summary.json")
    if os.path.exists(summary_path):
        with open(summary_path) as f:
            return json.load(f)
    return {}


def _build_feature_vector(features: dict) -> list:
    """Build a feature vector in the correct order."""
    if _feature_names:
        return [features.get(name, 0) for name in _feature_names]
    else:
        from url_features import get_feature_names
        return [features.get(name, 0) for name in get_feature_names()]


if __name__ == "__main__":
    import sys

    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login.php",
        "http://paypal-login.suspicious-site.tk/verify",
        "https://github.com/user/repo",
    ]

    if len(sys.argv) > 1:
        test_urls = sys.argv[1:]

    for url in test_urls:
        try:
            result = predict_url(url)
            print(f"\nURL: {result['url']}")
            print(f"  Prediction:  {result['prediction']}")
            print(f"  Probability: {result['probability']}")
            print(f"  Model:       {result['model']}")
        except FileNotFoundError as e:
            print(f"Error: {e}")
            break
