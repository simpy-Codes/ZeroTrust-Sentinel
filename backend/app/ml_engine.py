import numpy as np
from sklearn.ensemble import IsolationForest


# --------------------------------------------------
# AI Behavioral Anomaly Detection Engine
# --------------------------------------------------

# Normal user behavior dataset
# Features:
# 1. Request frequency
# 2. Average response latency
# 3. Data volume
# 4. Failed authentication attempts
# 5. Unique endpoints accessed
normal_behavior = np.array([
    [5, 120, 200, 0, 3],
    [8, 110, 250, 0, 4],
    [10, 130, 300, 1, 4],
    [7, 100, 180, 0, 3],
    [12, 140, 350, 1, 5],
    [15, 125, 400, 0, 5],
    [9, 115, 220, 0, 3],
    [11, 135, 280, 1, 4],
    [6, 105, 190, 0, 3],
    [14, 145, 330, 1, 5],
    [10, 118, 260, 0, 4],
    [13, 128, 310, 0, 4],
    [8, 112, 210, 0, 3],
    [16, 138, 380, 1, 5],
    [12, 120, 290, 0, 4],
    [7, 108, 200, 0, 3],
])


# Train Isolation Forest
model = IsolationForest(
    n_estimators=150,
    contamination=0.10,
    random_state=42
)

model.fit(normal_behavior)


def detect_anomaly(
    request_frequency: int = 10,
    response_latency: float = 120,
    data_volume: float = 250,
    failed_auth_attempts: int = 0,
    unique_endpoints: int = 4,
):
    """
    Analyze API behavior and calculate anomaly score.
    """

    sample = np.array([[
        request_frequency,
        response_latency,
        data_volume,
        failed_auth_attempts,
        unique_endpoints
    ]])

    prediction = model.predict(sample)[0]

    decision_score = model.decision_function(sample)[0]

    # Convert model score into an easier 0-100 anomaly score
    anomaly_score = int(
        np.clip(
            50 - (decision_score * 100),
            0,
            100
        )
    )

    if prediction == -1:
        anomaly = True
    else:
        anomaly = False

    if anomaly_score >= 80:
        severity = "CRITICAL"
    elif anomaly_score >= 60:
        severity = "HIGH"
    elif anomaly_score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "anomaly_detected": anomaly,
        "anomaly_score": anomaly_score,
        "severity": severity,
        "model": "Isolation Forest",
        "features": {
            "request_frequency": request_frequency,
            "response_latency": response_latency,
            "data_volume": data_volume,
            "failed_auth_attempts": failed_auth_attempts,
            "unique_endpoints": unique_endpoints,
        }
    }