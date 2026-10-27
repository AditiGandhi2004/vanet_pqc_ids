import joblib
import pandas as pd

from ids.features import VANETFeatureExtractor


class VANETIDS:

    def __init__(self, model_path="results/vanet_ids_model.pkl"):
        self.model = joblib.load(model_path)
        self.feature_extractor = VANETFeatureExtractor()

        self.labels = {
            0: "NORMAL",
            1: "REPLAY",
            2: "SYBIL",
            3: "DOS",
            4: "TAMPERING"
        }

    def predict(self, message, previous_message=None):

        features = self.feature_extractor.extract(
            message,
            previous_message
        )

        dataframe = pd.DataFrame([features])

        prediction = self.model.predict(dataframe)[0]

        probabilities = self.model.predict_proba(dataframe)[0]

        confidence = max(probabilities)

        return {
            "label": int(prediction),
            "class": self.labels[int(prediction)],
            "confidence": float(confidence),
            "features": features
        }