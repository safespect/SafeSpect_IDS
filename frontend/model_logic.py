import joblib
import pandas as pd
import numpy as np
import shap

class SafeSpectAI:
    def __init__(self, model_path):
        try:
            # Load the model
            self.model = joblib.load(model_path)
            # Initialize SHAP explainer
            self.explainer = shap.TreeExplainer(self.model)
            print("✅ Model and XAI Explainer loaded successfully!")
        except Exception as e:
            self.model = None
            print(f"❌ Error loading model: {e}")

    def predict_and_explain(self, input_dict):
        # 1. Convert input to DataFrame
        df = pd.DataFrame([input_dict])
        
        # 2. Get Prediction
        prediction = self.model.predict(df)[0]
        probs = self.model.predict_proba(df)[0]
        confidence = max(probs)
        
        # 3. Generate SHAP values for explanation
        shap_values = self.explainer.shap_values(df)
        
        # Handle different SHAP output formats
        if isinstance(shap_values, list):
            # For binary classification in some models, SHAP returns a list
            current_shap = shap_values[int(prediction)][0]
        else:
            current_shap = shap_values[0]

        return {
            "result": "Malicious" if prediction == 1 else "Normal",
            "confidence": f"{round(confidence * 100, 2)}%",
            "explanation": {
                "features": list(df.columns),
                "impact": current_shap.tolist()
            }
        }