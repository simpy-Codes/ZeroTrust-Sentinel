from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text
from sqlalchemy.sql import func

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    role = Column(String(50), default="USER")
    trust_score = Column(Float, default=100.0)
    is_active = Column(Boolean, default=True)


class APIRequest(Base):
    __tablename__ = "api_requests"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False)
    endpoint = Column(String(255), nullable=False)
    method = Column(String(20), default="GET")
    ip_address = Column(String(100))
    device = Column(String(100))
    location = Column(String(100))
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(50), default="LOW")
    action = Column(String(50), default="ALLOW")
    timestamp = Column(DateTime(timezone=True), server_default=func.now())


class SecurityIncident(Base):
    __tablename__ = "security_incidents"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100))
    incident_type = Column(String(150))
    severity = Column(String(50))
    description = Column(Text)
    risk_score = Column(Float)
    status = Column(String(50), default="OPEN")
    timestamp = Column(DateTime(timezone=True), server_default=func.now())