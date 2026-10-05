def calculate_risk(
    request_frequency: int = 1,
    new_device: bool = False,
    unusual_location: bool = False,
    sensitive_endpoint: bool = False,
    unusual_time: bool = False,
    privilege_violation: bool = False,
):
    score = 0
    reasons = []

    # Request frequency
    if request_frequency > 100:
        score += 30
        reasons.append("Abnormally high request frequency")
    elif request_frequency > 50:
        score += 15
        reasons.append("Elevated request frequency")

    # Device
    if new_device:
        score += 20
        reasons.append("Unknown or new device detected")

    # Location
    if unusual_location:
        score += 20
        reasons.append("Unusual location detected")

    # Sensitive API
    if sensitive_endpoint:
        score += 15
        reasons.append("Sensitive endpoint accessed")

    # Time
    if unusual_time:
        score += 10
        reasons.append("Unusual access time")

    # Privilege
    if privilege_violation:
        score += 30
        reasons.append("Privilege violation detected")

    # Maximum score
    score = min(score, 100)

    # Risk level + action
    if score >= 80:
        risk_level = "CRITICAL"
        action = "BLOCK"
    elif score >= 60:
        risk_level = "HIGH"
        action = "CHALLENGE"
    elif score >= 30:
        risk_level = "MEDIUM"
        action = "MONITOR"
    else:
        risk_level = "LOW"
        action = "ALLOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "action": action,
        "reasons": reasons,
    }