
import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


DATASET = "results/vanet_ids_dataset.csv"
MODEL_FILE = "results/vanet_ids_model.pkl"


def main():
    print("=" * 55)
    print("   VANET RANDOM FOREST INTRUSION DETECTION")
    print("=" * 55)

    # Check dataset
    if not os.path.exists(DATASET):
        raise FileNotFoundError(
            f"Dataset not found: {DATASET}\n"
            "Run this script from the project root directory."
        )

    # Load dataset
    print("\n[1] Loading IDS dataset...")
    df = pd.read_csv(DATASET)

    if "label" not in df.columns:
        raise ValueError("Dataset must contain a 'label' column.")

    if df.empty:
        raise ValueError("Dataset is empty.")

    print(f"Dataset rows: {len(df)}")
    print(f"Dataset columns: {len(df.columns)}")
    print("\nClass distribution:")
    print(df["label"].value_counts().sort_index())

    # Prepare features and labels
    X = df.drop(columns=["label"])
    y = df["label"]

    if X.empty or X.shape[1] == 0:
        raise ValueError("Dataset has no feature columns.")

    # Split dataset into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print("\n[2] Dataset split")
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples : {len(X_test)}")

    # Train Random Forest
    print("\n[3] Training Random Forest IDS...")

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(X_train, y_train)

    print("Model training completed.")

    # Generate predictions
    print("\n[4] Generating predictions...")
    predictions = model.predict(X_test)

    # Calculate metrics
    accuracy = accuracy_score(y_test, predictions)

    precision = precision_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0
    )

    # Display evaluation metrics
    print("\n" + "=" * 55)
    print("          RANDOM FOREST EVALUATION RESULTS")
    print("=" * 55)

    print(f"Accuracy : {accuracy:.4f} ({accuracy * 100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision * 100:.2f}%)")
    print(f"Recall   : {recall:.4f} ({recall * 100:.2f}%)")
    print(f"F1-Score : {f1:.4f} ({f1 * 100:.2f}%)")

    # Classification report
    print("\n" + "=" * 55)
    print("             CLASSIFICATION REPORT")
    print("=" * 55)

    print(
        classification_report(
            y_test,
            predictions,
            labels=model.classes_,
            target_names=[str(label) for label in model.classes_],
            zero_division=0
        )
    )

    # Confusion matrix
    print("=" * 55)
    print("                CONFUSION MATRIX")
    print("=" * 55)
    print("Rows = Actual classes")
    print("Columns = Predicted classes")
    print("Class order:", list(model.classes_))

    cm = confusion_matrix(
        y_test,
        predictions,
        labels=model.classes_
    )

    print(cm)

    # Save trained model
    os.makedirs(os.path.dirname(MODEL_FILE), exist_ok=True)
    joblib.dump(model, MODEL_FILE)

    print("\n" + "=" * 55)
    print("Model saved successfully.")
    print(f"Model path: {MODEL_FILE}")
    print("=" * 55)


if __name__ == "__main__":
    main()
