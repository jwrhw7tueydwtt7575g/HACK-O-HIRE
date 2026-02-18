#!/usr/bin/env python3
"""
Incident Processor Service - Alert correlation, attack chain reconstruction,
and refined incident object creation for downstream enrichment.
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict

logger = logging.getLogger("ai-intelligence")


class IncidentProcessorService:
    """Correlates alerts, builds attack chains, and creates refined incidents"""

    def __init__(self, settings, opensearch_client=None, neo4j_client=None):
        self.settings = settings
        self.opensearch = opensearch_client
        self.neo4j = neo4j_client
        self.correlation_window_minutes = 60
        self.min_alerts_for_incident = 2

    async def process_wazuh_alert(self, alert: Dict) -> Optional[Dict]:
        """Process incoming Wazuh alert — correlate and potentially create incident"""
        alert_id = alert.get("id", str(uuid.uuid4()))
        user_id = alert.get("data", {}).get("user_id") or alert.get("agent", {}).get("name", "unknown")
        source_ip = alert.get("data", {}).get("source_ip") or alert.get("data", {}).get("srcip", "unknown")
        rule_level = alert.get("rule", {}).get("level", 0)

        # Index alert
        if self.opensearch:
            await self.opensearch.index_document(
                "banking-soc-ueba-alerts",
                alert_id,
                {**alert, "processed_by": "ai_intelligence", "processed_at": datetime.utcnow().isoformat()}
            )

        # Check for correlation with recent alerts
        correlated = await self._find_correlated_alerts(user_id, source_ip)

        if len(correlated) >= self.min_alerts_for_incident or rule_level >= 13:
            incident = await self._create_refined_incident(alert, correlated)
            return incident

        return None

    async def _find_correlated_alerts(self, user_id: str, source_ip: str) -> List[Dict]:
        """Find recent alerts correlated by user or source IP within time window"""
        if not self.opensearch:
            return []

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {
                            "gte": f"now-{self.correlation_window_minutes}m",
                            "lte": "now"
                        }}},
                    ],
                    "should": [
                        {"match": {"data.user_id": user_id}},
                        {"match": {"data.source_ip": source_ip}},
                        {"match": {"agent.name": user_id}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [{"@timestamp": "desc"}]
        }

        return await self.opensearch.search("banking-soc-ueba-alerts", query, size=50)

    async def _create_refined_incident(self, trigger_alert: Dict,
                                        correlated_alerts: List[Dict]) -> Dict:
        """Create refined incident object with aggregated context"""
        incident_id = f"INC-AI-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        all_alerts = [trigger_alert] + correlated_alerts

        # Aggregate entities and systems
        entities = set()
        systems = set()
        mitre_techniques = set()
        max_severity = 0

        for alert in all_alerts:
            user = alert.get("data", {}).get("user_id") or alert.get("agent", {}).get("name")
            if user:
                entities.add(user)

            system = (alert.get("data", {}).get("computer_name")
                      or alert.get("agent", {}).get("name"))
            if system:
                systems.add(system)

            mitre = alert.get("rule", {}).get("mitre", {})
            if isinstance(mitre, dict):
                for tech_id in mitre.get("id", []):
                    mitre_techniques.add(tech_id)

            level = alert.get("rule", {}).get("level", 0)
            max_severity = max(max_severity, level)

        # Map severity level to string
        if max_severity >= 13:
            severity = "critical"
        elif max_severity >= 10:
            severity = "high"
        elif max_severity >= 6:
            severity = "medium"
        else:
            severity = "low"

        # Build attack chain via Neo4j
        attack_chain = None
        if self.neo4j and entities:
            primary_entity = list(entities)[0]
            chain_data = await self.neo4j.get_attack_chain(primary_entity)
            if chain_data:
                attack_chain = {
                    "chain_id": str(uuid.uuid4()),
                    "nodes": chain_data,
                    "entity_count": len(entities),
                }

        trigger_rule = trigger_alert.get("rule", {})
        incident = {
            "incident_id": incident_id,
            "title": f"AI-Detected: {trigger_rule.get('description', 'Behavioral anomaly')}",
            "description": (
                f"Correlated {len(all_alerts)} alerts involving "
                f"{len(entities)} entities across {len(systems)} systems. "
                f"MITRE techniques: {', '.join(mitre_techniques) or 'N/A'}."
            ),
            "severity": severity,
            "status": "new",
            "confidence": min(0.95, 0.6 + 0.05 * len(all_alerts)),
            "risk_score": min(100.0, max_severity * 7.5),
            "timestamp": datetime.utcnow().isoformat(),
            "source": "ai_intelligence",
            "affected_entities": list(entities),
            "affected_assets": list(systems),
            "mitre_techniques": list(mitre_techniques),
            "attack_chain": attack_chain,
            "alert_count": len(all_alerts),
            "original_alerts": [
                {
                    "alert_id": a.get("id", "unknown"),
                    "rule_id": a.get("rule", {}).get("id"),
                    "rule_description": a.get("rule", {}).get("description"),
                    "level": a.get("rule", {}).get("level"),
                    "timestamp": a.get("timestamp"),
                }
                for a in all_alerts[:20]
            ],
        }

        # Index to OpenSearch for enrichment layer to pick up
        if self.opensearch:
            await self.opensearch.index_document(
                "banking-soc-incidents", incident_id, incident
            )
            logger.info(f"Created refined incident {incident_id}: {severity}, "
                        f"{len(all_alerts)} alerts, {len(entities)} entities")

        return incident

    async def process_batch_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Process a batch of alerts and return any created incidents"""
        incidents = []
        for alert in alerts:
            incident = await self.process_wazuh_alert(alert)
            if incident:
                incidents.append(incident)
        return incidents
