def calculate_trust_decision(
    rule_risk_score: int,
    anomaly_score: int,
    new_device: bool = False,
    unusual_location: bool = False,
    sensitive_endpoint: bool = False,
    privilege_violation: bool = False,
):
    """
    Combines rule-based risk and AI behavioral anomaly
    into a Zero-Trust security decision.
    """

    # --------------------------------------------------
    # Weighted Risk Calculation
    # --------------------------------------------------

    combined_risk = (
        (rule_risk_score * 0.60)
        + (anomaly_score * 0.40)
    )

    # Additional zero-trust context
    if new_device:
        combined_risk += 5

    if unusual_location:
        combined_risk += 5

    if sensitive_endpoint:
        combined_risk += 5

    if privilege_violation:
        combined_risk += 10

    # Keep score between 0 and 100
    combined_risk = min(int(combined_risk), 100)

    # --------------------------------------------------
    # Dynamic Trust Score
    # --------------------------------------------------

    trust_score = max(0, 100 - combined_risk)

    # --------------------------------------------------
    # Zero-Trust Policy
    # --------------------------------------------------

    if combined_risk >= 80:
        action = "BLOCK"
        risk_level = "CRITICAL"
        explanation = "High-confidence malicious behavior detected."

    elif combined_risk >= 60:
        action = "CHALLENGE"
        risk_level = "HIGH"
        explanation = "User identity is valid but behavior is suspicious."

    elif combined_risk >= 30:
        action = "MONITOR"
        risk_level = "MEDIUM"
        explanation = "Behavior requires continuous monitoring."

    else:
        action = "ALLOW"
        risk_level = "LOW"
        explanation = "Behavior matches trusted activity patterns."

    return {
        "combined_risk_score": combined_risk,
        "dynamic_trust_score": trust_score,
        "risk_level": risk_level,
        "action": action,
        "explanation": explanation,
        "policy": "Zero-Trust Continuous Verification",
    }