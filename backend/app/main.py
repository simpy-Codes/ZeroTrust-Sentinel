from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import Base, engine, get_db
from models import User, APIRequest, SecurityIncident

from risk_engine import calculate_risk
from ml_engine import detect_anomaly
from policy_engine import calculate_trust_decision


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

Base.metadata.create_all(bind=engine)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="ZeroTrust Sentinel API",
    description=(
        "AI-Powered Zero-Trust API Security "
        "& Behavioral Anomaly Detection Platform"
    ),
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "project": "ZeroTrust Sentinel",
        "status": "online",
        "message": "Zero-Trust Security API is running",
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "ZeroTrust Sentinel Backend",
    }


# ============================================================
# SECURITY STATUS
# ============================================================

@app.get("/api/security-status")
def security_status():
    return {
        "system": "ZeroTrust Sentinel",
        "status": "PROTECTED",
        "threat_level": "LOW",
        "active_monitoring": True,
    }


# ============================================================
# DASHBOARD STATS
# ============================================================

@app.get("/api/dashboard/stats")
def dashboard_stats(db: Session = Depends(get_db)):

    total_users = db.query(User).count()

    total_requests = db.query(APIRequest).count()

    total_incidents = db.query(SecurityIncident).count()

    blocked_requests = (
        db.query(APIRequest)
        .filter(APIRequest.action == "BLOCK")
        .count()
    )

    high_risk_events = (
        db.query(APIRequest)
        .filter(
            APIRequest.risk_level.in_(
                ["HIGH", "CRITICAL"]
            )
        )
        .count()
    )

    monitored_requests = (
        db.query(APIRequest)
        .filter(APIRequest.action == "MONITOR")
        .count()
    )

    challenged_requests = (
        db.query(APIRequest)
        .filter(APIRequest.action == "CHALLENGE")
        .count()
    )

    allowed_requests = (
        db.query(APIRequest)
        .filter(APIRequest.action == "ALLOW")
        .count()
    )

    critical_incidents = (
        db.query(SecurityIncident)
        .filter(SecurityIncident.severity == "CRITICAL")
        .count()
    )

    trust_values = (
        db.query(User.trust_score)
        .all()
    )

    if trust_values:
        avg_trust = round(
            sum(
                row[0]
                for row in trust_values
                if row[0] is not None
            )
            / len(
                [
                    row
                    for row in trust_values
                    if row[0] is not None
                ]
            ),
            1,
        )
    else:
        avg_trust = 100.0

    return {
        "total_users": total_users,
        "total_requests": total_requests,
        "total_incidents": total_incidents,
        "blocked_requests": blocked_requests,
        "high_risk_events": high_risk_events,
        "monitored_requests": monitored_requests,
        "challenged_requests": challenged_requests,
        "allowed_requests": allowed_requests,
        "critical_incidents": critical_incidents,
        "average_trust_score": avg_trust,
        "system_status": "PROTECTED",
    }


# ============================================================
# DASHBOARD EVENTS
# ============================================================

@app.get("/api/dashboard/events")
def dashboard_events(
    limit: int = 20,
    db: Session = Depends(get_db),
):

    events = (
        db.query(APIRequest)
        .order_by(APIRequest.timestamp.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": event.id,
            "user": event.username,
            "endpoint": event.endpoint,
            "method": event.method,
            "ip": event.ip_address,
            "device": event.device,
            "location": event.location,
            "risk": event.risk_score,
            "risk_level": event.risk_level,
            "action": event.action,
            "timestamp": (
                event.timestamp.isoformat()
                if event.timestamp
                else None
            ),
        }
        for event in events
    ]


# ============================================================
# SECURITY INCIDENTS
# ============================================================

@app.get("/api/dashboard/incidents")
def dashboard_incidents(
    limit: int = 20,
    db: Session = Depends(get_db),
):

    incidents = (
        db.query(SecurityIncident)
        .order_by(SecurityIncident.timestamp.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": incident.id,
            "username": incident.username,
            "incident_type": incident.incident_type,
            "severity": incident.severity,
            "description": incident.description,
            "risk_score": incident.risk_score,
            "status": incident.status,
            "timestamp": (
                incident.timestamp.isoformat()
                if incident.timestamp
                else None
            ),
        }
        for incident in incidents
    ]
    # ============================================================
# USERS
# ============================================================

@app.get("/api/dashboard/users")
def dashboard_users(
    db: Session = Depends(get_db),
):

    users = (
        db.query(User)
        .order_by(User.trust_score.asc())
        .all()
    )

    return [
        {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "trust_score": user.trust_score,
            "is_active": user.is_active,
        }
        for user in users
    ]


# ============================================================
# API REQUESTS
# ============================================================

@app.get("/api/dashboard/requests")
def dashboard_requests(
    limit: int = 50,
    db: Session = Depends(get_db),
):

    requests = (
        db.query(APIRequest)
        .order_by(APIRequest.timestamp.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": request.id,
            "username": request.username,
            "endpoint": request.endpoint,
            "method": request.method,
            "ip_address": request.ip_address,
            "device": request.device,
            "location": request.location,
            "risk_score": request.risk_score,
            "risk_level": request.risk_level,
            "action": request.action,
            "timestamp": (
                request.timestamp.isoformat()
                if request.timestamp
                else None
            ),
        }
        for request in requests
    ]


# ============================================================
# RISK ENGINE
# ============================================================

@app.post("/api/analyze-request")
def analyze_request(
    request_frequency: int = 1,
    new_device: bool = False,
    unusual_location: bool = False,
    sensitive_endpoint: bool = False,
    unusual_time: bool = False,
    privilege_violation: bool = False,
):

    result = calculate_risk(
        request_frequency=request_frequency,
        new_device=new_device,
        unusual_location=unusual_location,
        sensitive_endpoint=sensitive_endpoint,
        unusual_time=unusual_time,
        privilege_violation=privilege_violation,
    )

    return {
        "request": {
            "frequency": request_frequency,
            "new_device": new_device,
            "unusual_location": unusual_location,
            "sensitive_endpoint": sensitive_endpoint,
            "unusual_time": unusual_time,
            "privilege_violation": privilege_violation,
        },
        "security_decision": result,
    }


# ============================================================
# AI / MACHINE LEARNING ANALYSIS
# ============================================================

@app.post("/api/ml/analyze")
def ml_analyze_request(
    request_frequency: int = 10,
    response_latency: float = 120,
    data_volume: float = 250,
    failed_auth_attempts: int = 0,
    unique_endpoints: int = 4,
):

    result = detect_anomaly(
        request_frequency=request_frequency,
        response_latency=response_latency,
        data_volume=data_volume,
        failed_auth_attempts=failed_auth_attempts,
        unique_endpoints=unique_endpoints,
    )

    return {
        "ai_engine": "Behavioral Anomaly Detection",
        "algorithm": "Isolation Forest",
        "analysis": result,
    }


# ============================================================
# ZERO-TRUST ANALYSIS
# ============================================================

@app.post("/api/zero-trust/analyze")
def zero_trust_analysis(
    request_frequency: int = 10,
    response_latency: float = 120,
    data_volume: float = 250,
    failed_auth_attempts: int = 0,
    unique_endpoints: int = 4,
    new_device: bool = False,
    unusual_location: bool = False,
    sensitive_endpoint: bool = False,
    unusual_time: bool = False,
    privilege_violation: bool = False,
):

    # --------------------------------------------------------
    # RULE ENGINE
    # --------------------------------------------------------

    rule_result = calculate_risk(
        request_frequency=request_frequency,
        new_device=new_device,
        unusual_location=unusual_location,
        sensitive_endpoint=sensitive_endpoint,
        unusual_time=unusual_time,
        privilege_violation=privilege_violation,
    )

    # --------------------------------------------------------
    # AI ENGINE
    # --------------------------------------------------------

    ml_result = detect_anomaly(
        request_frequency=request_frequency,
        response_latency=response_latency,
        data_volume=data_volume,
        failed_auth_attempts=failed_auth_attempts,
        unique_endpoints=unique_endpoints,
    )

    # --------------------------------------------------------
    # ZERO-TRUST POLICY ENGINE
    # --------------------------------------------------------

    policy_result = calculate_trust_decision(
        rule_risk_score=rule_result["risk_score"],
        anomaly_score=ml_result["anomaly_score"],
        new_device=new_device,
        unusual_location=unusual_location,
        sensitive_endpoint=sensitive_endpoint,
        privilege_violation=privilege_violation,
    )

    return {
        "zero_trust_engine": "ACTIVE",
        "rule_engine": rule_result,
        "ai_behavior_engine": ml_result,
        "final_security_decision": policy_result,
    }
    # ============================================================
# DEMO ATTACK SIMULATOR
# ============================================================

@app.post("/api/demo/attack")
def demo_attack(
    db: Session = Depends(get_db),
):

    # --------------------------------------------------------
    # Simulated suspicious request
    # --------------------------------------------------------

    request_frequency = 500
    response_latency = 900
    data_volume = 10000
    failed_auth_attempts = 15
    unique_endpoints = 30

    new_device = True
    unusual_location = True
    sensitive_endpoint = True
    unusual_time = True
    privilege_violation = True

    # --------------------------------------------------------
    # Rule-based risk analysis
    # --------------------------------------------------------

    rule_result = calculate_risk(
        request_frequency=request_frequency,
        new_device=new_device,
        unusual_location=unusual_location,
        sensitive_endpoint=sensitive_endpoint,
        unusual_time=unusual_time,
        privilege_violation=privilege_violation,
    )

    # --------------------------------------------------------
    # AI behavioral analysis
    # --------------------------------------------------------

    ml_result = detect_anomaly(
        request_frequency=request_frequency,
        response_latency=response_latency,
        data_volume=data_volume,
        failed_auth_attempts=failed_auth_attempts,
        unique_endpoints=unique_endpoints,
    )

    # --------------------------------------------------------
    # Zero-Trust decision
    # --------------------------------------------------------

    policy_result = calculate_trust_decision(
        rule_risk_score=rule_result["risk_score"],
        anomaly_score=ml_result["anomaly_score"],
        new_device=new_device,
        unusual_location=unusual_location,
        sensitive_endpoint=sensitive_endpoint,
        privilege_violation=privilege_violation,
    )

    # --------------------------------------------------------
    # Save API request to database
    # --------------------------------------------------------

    api_request = APIRequest(
        username="suspicious.client",
        endpoint="/api/admin/export",
        method="POST",
        ip_address="185.220.101.45",
        device="Unknown Device",
        location="Unknown Location",
        risk_score=policy_result["combined_risk_score"],
        risk_level=policy_result["risk_level"],
        action=policy_result["action"],
    )

    db.add(api_request)

    # --------------------------------------------------------
    # Create security incident
    # --------------------------------------------------------

    incident = SecurityIncident(
        username="suspicious.client",
        incident_type="Zero-Trust Behavioral Attack",
        severity=policy_result["risk_level"],
        description=(
            "Suspicious API behavior detected: "
            "high request frequency, unknown device, "
            "unusual location, sensitive endpoint access "
            "and privilege violation."
        ),
        risk_score=policy_result["combined_risk_score"],
        status="OPEN",
    )

    db.add(incident)

    # --------------------------------------------------------
    # Update suspicious user's trust score
    # --------------------------------------------------------

    suspicious_user = (
        db.query(User)
        .filter(
            User.username == "suspicious.client"
        )
        .first()
    )

    if suspicious_user:
        suspicious_user.trust_score = (
            policy_result["dynamic_trust_score"]
        )

    db.commit()

    # --------------------------------------------------------
    # Final response
    # --------------------------------------------------------

    return {
        "simulation": "ATTACK_SIMULATION",
        "status": "ATTACK_DETECTED",

        "attack_profile": {
            "request_frequency": request_frequency,
            "response_latency": response_latency,
            "data_volume": data_volume,
            "failed_auth_attempts": failed_auth_attempts,
            "unique_endpoints": unique_endpoints,
            "new_device": new_device,
            "unusual_location": unusual_location,
            "sensitive_endpoint": sensitive_endpoint,
            "unusual_time": unusual_time,
            "privilege_violation": privilege_violation,
        },

        "rule_engine": rule_result,

        "ai_behavior_engine": ml_result,

        "zero_trust_decision": policy_result,

        "database": {
            "api_request_logged": True,
            "security_incident_created": True,
            "user_trust_score_updated": True,
        },

        "message": (
            "Zero-Trust policy evaluated the request "
            "and applied the final security action."
        ),
    }


# ============================================================
# SERVER STARTUP INFORMATION
# ============================================================

@app.on_event("startup")
def startup_event():

    print("=" * 60)
    print(" ZERO TRUST SENTINEL BACKEND")
    print("=" * 60)
    print(" API Security Engine : ACTIVE")
    print(" AI Anomaly Engine   : ACTIVE")
    print(" Risk Engine         : ACTIVE")
    print(" Zero-Trust Policy   : ACTIVE")
    print(" Database            : SQLite")
    print("=" * 60)