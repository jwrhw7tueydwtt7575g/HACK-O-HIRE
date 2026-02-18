#!/usr/bin/env python3
"""Pydantic data models for AI Intelligence behavioral analytics"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum
from pydantic import BaseModel, Field


class AnomalyType(str, Enum):
    """Types of anomalies detected"""
    TEMPORAL = "temporal"
    GEOGRAPHIC = "geographic"
    TRANSACTIONAL = "transactional"
    ACCESS_PATTERN = "access_pattern"
    PEER_DEVIATION = "peer_deviation"
    BEHAVIORAL = "behavioral"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class UserBaseline(BaseModel):
    """Behavioral baseline for a user entity"""
    user_id: str
    baseline_start: datetime
    baseline_end: datetime
    login_times: Dict[str, Any] = Field(default_factory=dict,
        description="Mean/std of login hours by day of week")
    session_durations: Dict[str, float] = Field(default_factory=dict,
        description="Mean/std/max session duration in minutes")
    transaction_volumes: Dict[str, float] = Field(default_factory=dict,
        description="Mean/std/max daily transaction count and value")
    access_patterns: Dict[str, Any] = Field(default_factory=dict,
        description="Typical endpoints, resources, and frequencies")
    geo_locations: List[str] = Field(default_factory=list,
        description="Known login locations (country codes)")
    peer_group_id: Optional[str] = None
    last_updated: datetime = Field(default_factory=datetime.utcnow)


class AnomalyResult(BaseModel):
    """Result from anomaly detection models"""
    anomaly_id: str
    entity_id: str
    entity_type: str = "user"
    anomaly_type: AnomalyType
    detection_method: str = Field(description="isolation_forest|autoencoder|hbos|graph")
    anomaly_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    features: Dict[str, float] = Field(default_factory=dict)
    baseline_deviation: Dict[str, Any] = Field(default_factory=dict,
        description="How far from baseline each feature deviates")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_event: Optional[Dict[str, Any]] = None


class RiskScore(BaseModel):
    """Composite risk score for an entity"""
    entity_id: str
    entity_type: str = "user"
    overall_score: float = Field(ge=0.0, le=100.0)
    risk_level: RiskLevel
    component_scores: Dict[str, float] = Field(default_factory=dict,
        description="time, location, transaction, access, peer scores")
    contributing_anomalies: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class BehavioralProfile(BaseModel):
    """Full behavioral profile for an entity"""
    entity_id: str
    entity_type: str = "user"
    baseline: Optional[UserBaseline] = None
    current_risk: Optional[RiskScore] = None
    recent_anomalies: List[AnomalyResult] = Field(default_factory=list)
    peer_group: Optional[str] = None
    peer_similarity_score: Optional[float] = None
    profile_completeness: float = Field(default=0.0, ge=0.0, le=1.0)
    last_activity: Optional[datetime] = None


class AlertContext(BaseModel):
    """Wazuh alert with behavioral context from UEBA"""
    alert_id: str
    rule_id: int
    rule_description: str
    severity: int
    timestamp: datetime
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    mitre_ids: List[str] = Field(default_factory=list)
    risk_score: Optional[float] = None
    anomaly_context: Optional[AnomalyResult] = None


class AttackChain(BaseModel):
    """Reconstructed attack chain linking related alerts"""
    chain_id: str
    alerts: List[AlertContext] = Field(default_factory=list)
    entities_involved: List[str] = Field(default_factory=list)
    systems_affected: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    chain_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    total_risk_score: float = Field(default=0.0)


class RefinedIncident(BaseModel):
    """Refined incident object — output of AI Intelligence layer (Layer 4.4)"""
    incident_id: str
    title: str
    description: str
    severity: str
    status: str = "new"
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(default=0.0)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str = "ai_intelligence"
    attack_chain: Optional[AttackChain] = None
    behavioral_context: List[AnomalyResult] = Field(default_factory=list)
    affected_entities: List[str] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    original_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    raw_logs: List[Dict[str, Any]] = Field(default_factory=list)
