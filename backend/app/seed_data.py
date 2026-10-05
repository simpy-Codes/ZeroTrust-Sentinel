from datetime import datetime, timedelta

from database import Base, SessionLocal, engine
from models import User, APIRequest, SecurityIncident


# Create database tables if they do not already exist
Base.metadata.create_all(bind=engine)


def seed_database():
    db = SessionLocal()

    try:
        # ---------------------------------------------------------
        # 1. CLEAR OLD DEMO DATA
        # ---------------------------------------------------------
        db.query(SecurityIncident).delete()
        db.query(APIRequest).delete()
        db.query(User).delete()
        db.commit()

        # ---------------------------------------------------------
        # 2. DEMO USERS
        # ---------------------------------------------------------
        users = [
            User(
                username="admin@sentinel.io",
                role="ADMIN",
                trust_score=96,
                is_active=True,
            ),
            User(
                username="security.admin",
                role="SECURITY_ADMIN",
                trust_score=91,
                is_active=True,
            ),
            User(
                username="rahul.dev",
                role="DEVELOPER",
                trust_score=87,
                is_active=True,
            ),
            User(
                username="priya.analyst",
                role="ANALYST",
                trust_score=82,
                is_active=True,
            ),
            User(
                username="simpi.user",
                role="USER",
                trust_score=94,
                is_active=True,
            ),
            User(
                username="api-service",
                role="SERVICE",
                trust_score=98,
                is_active=True,
            ),
            User(
                username="suspicious.client",
                role="USER",
                trust_score=28,
                is_active=True,
            ),
            User(
                username="unknown_client",
                role="UNKNOWN",
                trust_score=12,
                is_active=False,
            ),
        ]

        db.add_all(users)
        db.commit()

        # ---------------------------------------------------------
        # 3. DEMO API REQUESTS
        # ---------------------------------------------------------
        now = datetime.utcnow()

        requests = [
            APIRequest(
                username="admin@sentinel.io",
                endpoint="/api/dashboard",
                method="GET",
                ip_address="10.10.1.15",
                device="Trusted Windows Laptop",
                location="Ranchi, Jharkhand",
                risk_score=8,
                risk_level="LOW",
                action="ALLOW",
                timestamp=now - timedelta(minutes=2),
            ),

            APIRequest(
                username="simpi.user",
                endpoint="/api/profile",
                method="GET",
                ip_address="10.10.2.21",
                device="Android Mobile",
                location="Jamshedpur, Jharkhand",
                risk_score=14,
                risk_level="LOW",
                action="ALLOW",
                timestamp=now - timedelta(minutes=4),
            ),

            APIRequest(
                username="rahul.dev",
                endpoint="/api/projects",
                method="GET",
                ip_address="10.10.3.17",
                device="Trusted MacBook",
                location="Bengaluru, Karnataka",
                risk_score=22,
                risk_level="LOW",
                action="ALLOW",
                timestamp=now - timedelta(minutes=7),
            ),

            APIRequest(
                username="priya.analyst",
                endpoint="/api/analytics",
                method="GET",
                ip_address="10.10.4.31",
                device="Corporate Laptop",
                location="Ranchi, Jharkhand",
                risk_score=31,
                risk_level="MEDIUM",
                action="MONITOR",
                timestamp=now - timedelta(minutes=10),
            ),

            APIRequest(
                username="api-service",
                endpoint="/api/data/sync",
                method="POST",
                ip_address="10.10.5.50",
                device="Internal Service",
                location="AWS Internal Network",
                risk_score=18,
                risk_level="LOW",
                action="ALLOW",
                timestamp=now - timedelta(minutes=13),
            ),

            APIRequest(
                username="rahul.dev",
                endpoint="/api/users",
                method="GET",
                ip_address="10.10.3.17",
                device="New Browser Session",
                location="Bengaluru, Karnataka",
                risk_score=48,
                risk_level="MEDIUM",
                action="MONITOR",
                timestamp=now - timedelta(minutes=16),
            ),

            APIRequest(
                username="priya.analyst",
                endpoint="/api/reports/export",
                method="POST",
                ip_address="10.10.4.31",
                device="Unknown Browser",
                location="Kolkata, West Bengal",
                risk_score=64,
                risk_level="HIGH",
                action="CHALLENGE",
                timestamp=now - timedelta(minutes=20),
            ),

            APIRequest(
                username="suspicious.client",
                endpoint="/api/auth/login",
                method="POST",
                ip_address="185.220.44.18",
                device="Unknown Device",
                location="Unknown Location",
                risk_score=78,
                risk_level="HIGH",
                action="CHALLENGE",
                timestamp=now - timedelta(minutes=24),
            ),

            APIRequest(
                username="suspicious.client",
                endpoint="/api/admin/users",
                method="GET",
                ip_address="185.220.44.18",
                device="Untrusted Device",
                location="Unknown Location",
                risk_score=91,
                risk_level="CRITICAL",
                action="BLOCK",
                timestamp=now - timedelta(minutes=28),
            ),

            APIRequest(
                username="unknown_client",
                endpoint="/api/admin/config",
                method="PUT",
                ip_address="203.0.113.45",
                device="Unknown Device",
                location="Unknown Location",
                risk_score=97,
                risk_level="CRITICAL",
                action="BLOCK",
                timestamp=now - timedelta(minutes=31),
            ),

            APIRequest(
                username="unknown_client",
                endpoint="/api/secrets",
                method="GET",
                ip_address="203.0.113.45",
                device="Untrusted Device",
                location="Unknown Location",
                risk_score=100,
                risk_level="CRITICAL",
                action="BLOCK",
                timestamp=now - timedelta(minutes=33),
            ),

            APIRequest(
                username="admin@sentinel.io",
                endpoint="/api/audit/logs",
                method="GET",
                ip_address="10.10.1.15",
                device="Trusted Windows Laptop",
                location="Ranchi, Jharkhand",
                risk_score=12,
                risk_level="LOW",
                action="ALLOW",
                timestamp=now - timedelta(minutes=37),
            ),

            APIRequest(
                username="simpi.user",
                endpoint="/api/notifications",
                method="GET",
                ip_address="10.10.2.21",
                device="Android Mobile",
                location="Jamshedpur, Jharkhand",
                risk_score=27,
                risk_level="LOW",
                action="ALLOW",
                timestamp=now - timedelta(minutes=41),
            ),

            APIRequest(
                username="rahul.dev",
                endpoint="/api/deployments",
                method="POST",
                ip_address="10.10.3.17",
                device="Trusted MacBook",
                location="Bengaluru, Karnataka",
                risk_score=57,
                risk_level="MEDIUM",
                action="MONITOR",
                timestamp=now - timedelta(minutes=45),
            ),

            APIRequest(
                username="suspicious.client",
                endpoint="/api/payments",
                method="POST",
                ip_address="185.220.44.18",
                device="Untrusted Device",
                location="Unknown Location",
                risk_score=88,
                risk_level="CRITICAL",
                action="BLOCK",
                timestamp=now - timedelta(minutes=49),
            ),
        ]

        db.add_all(requests)
        db.commit()

        # ---------------------------------------------------------
        # 4. SECURITY INCIDENTS
        # ---------------------------------------------------------
        incidents = [
            SecurityIncident(
                username="suspicious.client",
                incident_type="Privilege Escalation",
                severity="CRITICAL",
                description=(
                    "User attempted to access an administrative endpoint "
                    "without sufficient privileges."
                ),
                risk_score=91,
                status="OPEN",
                timestamp=now - timedelta(minutes=28),
            ),

            SecurityIncident(
                username="unknown_client",
                incident_type="Unauthorized API Access",
                severity="CRITICAL",
                description=(
                    "Unknown device attempted to access a restricted "
                    "configuration endpoint."
                ),
                risk_score=97,
                status="OPEN",
                timestamp=now - timedelta(minutes=31),
            ),

            SecurityIncident(
                username="unknown_client",
                incident_type="Sensitive Data Access",
                severity="CRITICAL",
                description=(
                    "Blocked attempt to access sensitive secrets endpoint "
                    "from an untrusted device."
                ),
                risk_score=100,
                status="OPEN",
                timestamp=now - timedelta(minutes=33),
            ),

            SecurityIncident(
                username="priya.analyst",
                incident_type="Unusual Location",
                severity="HIGH",
                description=(
                    "Sensitive report export request originated from a "
                    "new geographic location."
                ),
                risk_score=64,
                status="INVESTIGATING",
                timestamp=now - timedelta(minutes=20),
            ),

            SecurityIncident(
                username="suspicious.client",
                incident_type="Abnormal Login Behavior",
                severity="HIGH",
                description=(
                    "Multiple authentication requests detected from an "
                    "unknown device."
                ),
                risk_score=78,
                status="OPEN",
                timestamp=now - timedelta(minutes=24),
            ),

            SecurityIncident(
                username="rahul.dev",
                incident_type="Behavioral Anomaly",
                severity="MEDIUM",
                description=(
                    "Request pattern differs from the user's normal "
                    "behavioral baseline."
                ),
                risk_score=57,
                status="MONITORING",
                timestamp=now - timedelta(minutes=45),
            ),
        ]

        db.add_all(incidents)
        db.commit()

        # ---------------------------------------------------------
        # 5. DISPLAY SUMMARY
        # ---------------------------------------------------------
        user_count = db.query(User).count()
        request_count = db.query(APIRequest).count()
        incident_count = db.query(SecurityIncident).count()

        print()
        print("=" * 60)
        print("       ZERO TRUST SENTINEL - DATABASE SEEDED")
        print("=" * 60)
        print(f"Users created       : {user_count}")
        print(f"API requests created: {request_count}")
        print(f"Incidents created   : {incident_count}")
        print("=" * 60)
        print("Database: zerotrust.db")
        print("Status  : READY")
        print("=" * 60)
        print()

    except Exception as error:
        db.rollback()
        print()
        print("ERROR WHILE SEEDING DATABASE")
        print(error)
        print()

    finally:
        db.close()


if __name__ == "__main__":
    seed_database()