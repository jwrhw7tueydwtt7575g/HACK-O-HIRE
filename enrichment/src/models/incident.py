#!/usr/bin/env python3
"""Incident data models for enrichment and playbook generation"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Incident severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    """Incident lifecycle status"""
    NEW = "new"
    ENRICHING = "enriching"
    ENRICHED = "enriched"
    ANALYZING = "analyzing"
    RESPONDING = "responding"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CVEMatch(BaseModel):
    """CVE vulnerability match"""
    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    exploit_available: bool = False
    in_cisa_kev: bool = False
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    references: List[str] = Field(default_factory=list)
    cwe: Optional[str] = None
    affected_products: List[str] = Field(default_factory=list)


class ThreatIntelMatch(BaseModel):
    """Threat intelligence IOC match"""
    ioc_value: str
    ioc_type: str  # ip, domain, hash, url
    source_feed: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = Field(default_factory=list)
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    malware_family: Optional[str] = None


class MITREAttackTechnique(BaseModel):
    """MITRE ATT&CK technique"""
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    detection: Optional[str] = None
    mitigation: Optional[str] = None


class AssetInfo(BaseModel):
    """Asset information"""
    asset_id: str
    asset_name: str
    asset_type: str  # server, workstation, database, application
    business_unit: str
    criticality_score: int  # 1-10
    owner: Optional[str] = None
    location: Optional[str] = None
    ip_addresses: List[str] = Field(default_factory=list)
    hostnames: List[str] = Field(default_factory=list)


class EnrichedIncident(BaseModel):
    """Enriched incident with threat intelligence and context"""
    # Core identification
    incident_id: str
    timestamp: datetime
    source: str = "wazuh"
    
    # Classification
    severity: SeverityLevel
    status: IncidentStatus = IncidentStatus.NEW
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=100.0)
    
    # Basic incident data
    title: str
    description: str
    affected_assets: List[str] = Field(default_factory=list)
    attack_techniques: List[str] = Field(default_factory=list)
    
    # Enrichment data
    cve_matches: List[CVEMatch] = Field(default_factory=list)
    threat_intel_matches: List[ThreatIntelMatch] = Field(default_factory=list)
    mitre_attack_context: Dict[str, Any] = Field(default_factory=dict)
    asset_information: List[AssetInfo] = Field(default_factory=list)
    asset_criticality_score: Optional[int] = None
    
    # Business context
    business_impact: Optional[str] = None
    affected_business_units: List[str] = Field(default_factory=list)
    estimated_financial_impact: Optional[float] = None
    
    # Geolocation
    geoip_data: Dict[str, Any] = Field(default_factory=dict)
    
    # Original data
    original_alerts: List[Dict] = Field(default_factory=list)
    raw_logs: List[str] = Field(default_factory=list)
    
    # Metadata
    enriched_at: Optional[datetime] = None
    enrichment_sources: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class ActionBlock(BaseModel):
    """SOAR action block"""
    action_id: str
    action_type: str
    priority: int = Field(ge=1, le=10)
    automated: bool = False
    approval_required: bool = False
    parameters: Dict[str, Any] = Field(default_factory=dict)
    expected_duration_seconds: int = 60
    rollback_action: Optional[str] = None
    success_criteria: str
    description: Optional[str] = None


class PlaybookResponse(BaseModel):
    """Complete playbook response from LLM"""
    # Identification
    incident_id: str
    playbook_id: Optional[str] = None
    generated_at: datetime
    model_used: str
    
    # LLM-generated content
    incident_analysis: str
    response_playbook: str
    executive_summary: str
    technical_documentation: str
    
    # Actionable outputs
    soar_actions: List[ActionBlock] = Field(default_factory=list)
    recommended_priority: str
    estimated_resolution_time_hours: int
    
    # Context
    compliance_considerations: List[str] = Field(default_factory=list)
    stakeholder_notifications: List[Dict] = Field(default_factory=list)
    
    # Quality metrics
    confidence_score: float = Field(ge=0.0, le=1.0)
    playbook_version: str = "1.0.0"
    
    # Status tracking
    status: str = "generated"
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None


class EnrichmentTask(BaseModel):
    """Enrichment task tracking"""
    task_id: str
    incident_id: str
    task_type: str
    status: str = "pending"
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    result: Optional[Dict] = None
