import joblib
import pandas as pd
import numpy as np
import shap

class SafeSpectAI:
    def __init__(self, model_path):
        # Always initialize attributes
        self.model = None
        self.explainer = None
        self.required_features = []

        try:
            self.model = joblib.load(model_path)
            self.explainer = shap.TreeExplainer(self.model)

            if not hasattr(self.model, "feature_names_in_"):
                raise ValueError("Model missing feature_names_in_")

            self.required_features = list(self.model.feature_names_in_)
            print(f"✅ Model loaded. Expected features: {len(self.required_features)}")

        except Exception as e:
            print(f"❌ Model initialization failed: {e}")

    def predict_and_explain(self, input_dict):
        if self.model is None or not self.required_features:
            raise RuntimeError("Model not initialized properly")

        # 1. Create a dictionary with ALL required features set to 0.0
        full_features = {feature: 0.0 for feature in self.required_features}

        # 2. Fill in received features
        for key, value in input_dict.items():
            if key in full_features:
                try:
                    full_features[key] = float(value)
                except:
                    full_features[key] = 0.0

        # 3. Convert to DataFrame
        df = pd.DataFrame([full_features])[self.required_features]

        # 4. Predict
        prediction = int(self.model.predict(df)[0])
        probs = self.model.predict_proba(df)[0]

        # 5. SHAP explain
        shap_values = self.explainer.shap_values(df)
        if isinstance(shap_values, list):
            impact = shap_values[prediction][0]
        else:
            impact = shap_values[0]

        return {
            "result": "ATTACK" if prediction != 0 else "BENIGN",
            "confidence": f"{round(float(probs[prediction]) * 100, 2)}%",
            "explanation": {
                "features": list(df.columns),
                "impact": impact.tolist()
            }
        }