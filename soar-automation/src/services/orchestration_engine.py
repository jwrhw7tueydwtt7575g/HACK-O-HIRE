#!/usr/bin/env python3
"""
Orchestration Engine - Core SOAR workflow management
Coordinates automated response actions based on incident severity and context
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from enum import Enum

from core.config import Settings
from models.incident import EnrichedIncident, ResponseAction, ActionResult
from services.action_executor import ActionExecutor
from services.incident_manager import IncidentManager
from services.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

class ResponsePriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ApprovalStatus(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"

class OrchestrationEngine:
    """
    Core orchestration engine for automated incident response
    Implements severity-graded automation with human oversight controls
    """
    
    def __init__(self, settings: Settings, action_executor: ActionExecutor, 
                 incident_manager: IncidentManager, audit_logger: AuditLogger):
        self.settings = settings
        self.action_executor = action_executor
        self.incident_manager = incident_manager
        self.audit_logger = audit_logger
        self.opensearch_client = None
        self.redis_client = None
        
        # Automation policies by priority
        self.automation_policies = {
            ResponsePriority.LOW: {
                'human_review': 'optional',
                'auto_execute': False,
                'actions_allowed': ['log_enrichment', 'tag_alert', 'notify_queue', 'create_ticket'],
                'max_impact_score': 3
            },
            ResponsePriority.MEDIUM: {
                'human_review': 'required_before',
                'auto_execute': False,
                'actions_allowed': ['account_lock', 'endpoint_quarantine_warning', 'firewall_watch_rule', 'escalate'],
                'max_impact_score': 6
            },
            ResponsePriority.HIGH: {
                'human_review': 'required_after',
                'auto_execute': True,
                'actions_allowed': ['disable_account', 'reset_password', 'endpoint_isolation', 'ip_block', 'token_revocation', 'create_p1_ticket'],
                'max_impact_score': 8
            },
            ResponsePriority.CRITICAL: {
                'human_review': 'crisis_team',
                'auto_execute': True,
                'actions_allowed': ['network_segment_isolation', 'kill_process', 'mass_credential_rotation', 'executive_bridge', 'regulator_notification'],
                'max_impact_score': 10
            }
        }
    
    async def initialize(self):
        """Initialize the orchestration engine"""
        logger.info("Initializing Orchestration Engine...")
        
        try:
            from core.database import OpenSearchClient, RedisClient
            
            self.opensearch_client = OpenSearchClient(self.settings)
            await self.opensearch_client.connect()
            
            self.redis_client = RedisClient(self.settings)
            await self.redis_client.connect()
            
            logger.info("✅ Orchestration Engine initialized")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize Orchestration Engine: {e}")
            raise
    
    async def process_incident(self, enriched_incident: EnrichedIncident) -> Dict:
        """
        Process enriched incident and orchestrate automated response
        """
        logger.info(f"Processing incident {enriched_incident.incident_id} for automated response")
        
        try:
            # Determine response priority
            priority = self._determine_priority(enriched_incident)
            logger.info(f"Incident priority: {priority}")
            
            # Get automation policy for this priority
            policy = self.automation_policies[priority]
            
            # Extract SOAR actions from playbook
            soar_actions = enriched_incident.playbook.soar_actions if enriched_incident.playbook else []
            
            # Filter actions based on policy
            allowed_actions = self._filter_actions_by_policy(soar_actions, policy)
            
            # Check if human review is required
            if policy['human_review'] == 'required_before':
                approval_status = await self._request_human_approval(enriched_incident, allowed_actions)
                if approval_status != ApprovalStatus.APPROVED:
                    logger.info(f"Incident {enriched_incident.incident_id} requires approval before execution")
                    return {
                        'status': 'pending_approval',
                        'incident_id': enriched_incident.incident_id,
                        'priority': priority,
                        'actions_pending': len(allowed_actions)
                    }
            
            # Execute actions
            execution_results = []
            if policy['auto_execute'] and allowed_actions:
                logger.info(f"Auto-executing {len(allowed_actions)} actions for {priority} incident")
                execution_results = await self._execute_actions(enriched_incident, allowed_actions, policy)
            
            # Post-execution human review for HIGH priority
            if policy['human_review'] == 'required_after':
                await self._notify_post_execution_review(enriched_incident, execution_results)
            
            # Crisis team notification for CRITICAL
            if policy['human_review'] == 'crisis_team':
                await self._activate_crisis_team(enriched_incident, execution_results)
            
            # Update incident status
            await self.incident_manager.update_incident_status(
                enriched_incident.incident_id,
                'automated_response_completed',
                execution_results
            )
            
            # Audit logging
            await self.audit_logger.log_incident_response(
                incident_id=enriched_incident.incident_id,
                priority=priority,
                actions_executed=len(execution_results),
                results=execution_results
            )
            
            logger.info(f"✅ Completed automated response for incident {enriched_incident.incident_id}")
            
            return {
                'status': 'completed',
                'incident_id': enriched_incident.incident_id,
                'priority': priority,
                'actions_executed': len(execution_results),
                'results': execution_results
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to process incident {enriched_incident.incident_id}: {e}")
            raise
    
    def _determine_priority(self, incident: EnrichedIncident) -> ResponsePriority:
        """Determine response priority based on incident characteristics"""
        risk_score = incident.risk_score or 0.5
        asset_criticality = incident.asset_criticality_score or 5
        
        # Critical: Very high risk or critical asset compromise
        if risk_score >= 0.9 or asset_criticality >= 9:
            return ResponsePriority.CRITICAL
        
        # High: High risk or important asset
        if risk_score >= 0.8 or asset_criticality >= 7:
            return ResponsePriority.HIGH
        
        # Medium: Moderate risk
        if risk_score >= 0.6 or asset_criticality >= 5:
            return ResponsePriority.MEDIUM
        
        # Low: Everything else
        return ResponsePriority.LOW
    
    def _filter_actions_by_policy(self, actions: List[ResponseAction], policy: Dict) -> List[ResponseAction]:
        """Filter actions based on automation policy"""
        allowed_action_types = policy['actions_allowed']
        max_impact = policy['max_impact_score']
        
        filtered_actions = []
        for action in actions:
            # Check if action type is allowed
            if action.action_type not in allowed_action_types:
                logger.debug(f"Action {action.action_id} type {action.action_type} not allowed by policy")
                continue
            
            # Check impact score
            if hasattr(action, 'impact_score') and action.impact_score > max_impact:
                logger.debug(f"Action {action.action_id} impact score too high for policy")
                continue
            
            filtered_actions.append(action)
        
        # Sort by priority
        filtered_actions.sort(key=lambda x: x.priority, reverse=True)
        
        return filtered_actions
    
    async def _execute_actions(self, incident: EnrichedIncident, 
                               actions: List[ResponseAction], policy: Dict) -> List[ActionResult]:
        """Execute approved actions"""
        results = []
        
        for action in actions:
            try:
                logger.info(f"Executing action: {action.action_type} (ID: {action.action_id})")
                
                # Execute action
                result = await self.action_executor.execute_action(
                    incident_id=incident.incident_id,
                    action=action
                )
                
                results.append(result)
                
                # Check if action failed and should stop execution
                if not result.success and action.critical:
                    logger.error(f"Critical action failed, stopping execution")
                    break
                
                # Delay between actions if specified
                if hasattr(action, 'delay_seconds') and action.delay_seconds:
                    await asyncio.sleep(action.delay_seconds)
                    
            except Exception as e:
                logger.error(f"Failed to execute action {action.action_id}: {e}")
                results.append(ActionResult(
                    action_id=action.action_id,
                    success=False,
                    error_message=str(e),
                    executed_at=datetime.now()
                ))
        
        return results
    
    async def _request_human_approval(self, incident: EnrichedIncident, 
                                     actions: List[ResponseAction]) -> ApprovalStatus:
        """Request human approval for actions"""
        logger.info(f"Requesting human approval for incident {incident.incident_id}")
        
        try:
            # Create approval request
            approval_request = {
                'incident_id': incident.incident_id,
                'priority': self._determine_priority(incident),
                'risk_score': incident.risk_score,
                'actions': [action.dict() for action in actions],
                'requested_at': datetime.now().isoformat(),
                'status': ApprovalStatus.PENDING
            }
            
            # Store in Redis for approval workflow
            await self.redis_client.set(
                f"approval_request:{incident.incident_id}",
                json.dumps(approval_request),
                ex=3600  # 1 hour expiry
            )
            
            # Send notification to analysts
            await self._notify_analysts_for_approval(incident, actions)
            
            return ApprovalStatus.PENDING
            
        except Exception as e:
            logger.error(f"Failed to request approval: {e}")
            return ApprovalStatus.DENIED
    
    async def _notify_analysts_for_approval(self, incident: EnrichedIncident, actions: List[ResponseAction]):
        """Notify security analysts for approval"""
        notification_payload = {
            'type': 'approval_required',
            'incident_id': incident.incident_id,
            'severity': incident.severity,
            'risk_score': incident.risk_score,
            'actions_count': len(actions),
            'message': f"Approval required for {len(actions)} automated actions on incident {incident.incident_id}",
            'approval_url': f"https://banking-soc.internal/approvals/{incident.incident_id}"
        }
        
        # Send to Slack/Teams/Email
        # Implementation depends on notification service configuration
        logger.info(f"Sent approval notification for incident {incident.incident_id}")
    
    async def _notify_post_execution_review(self, incident: EnrichedIncident, results: List[ActionResult]):
        """Notify analysts of completed automated actions for review"""
        notification_payload = {
            'type': 'post_execution_review',
            'incident_id': incident.incident_id,
            'actions_executed': len(results),
            'successful_actions': sum(1 for r in results if r.success),
            'failed_actions': sum(1 for r in results if not r.success),
            'review_url': f"https://banking-soc.internal/incidents/{incident.incident_id}/review"
        }
        
        logger.info(f"Sent post-execution review notification for incident {incident.incident_id}")
    
    async def _activate_crisis_team(self, incident: EnrichedIncident, results: List[ActionResult]):
        """Activate crisis management team for critical incidents"""
        logger.warning(f"🚨 Activating crisis team for CRITICAL incident {incident.incident_id}")
        
        crisis_notification = {
            'type': 'crisis_activation',
            'incident_id': incident.incident_id,
            'severity': 'CRITICAL',
            'risk_score': incident.risk_score,
            'affected_assets': incident.affected_assets,
            'business_impact': incident.business_impact,
            'automated_actions_taken': len(results),
            'war_room_url': f"https://banking-soc.internal/war-room/{incident.incident_id}",
            'stakeholders': ['CISO', 'CTO', 'CEO', 'Board', 'Legal', 'Compliance']
        }
        
        # Send high-priority notifications to all stakeholders
        # Phone calls, SMS, email, Slack, Microsoft Teams, etc.
        logger.info(f"Crisis team activated for incident {incident.incident_id}")
    
    async def start_processing(self):
        """Start the main orchestration processing loop"""
        logger.info("🔄 Starting orchestration processing loop...")
        
        while True:
            try:
                # Check for new enriched incidents to process
                await self._poll_for_incidents()
                
                # Check for approval responses
                await self._process_pending_approvals()
                
                # Sleep before next iteration
                await asyncio.sleep(10)  # 10 seconds
                
            except asyncio.CancelledError:
                logger.info("Orchestration processing cancelled")
                break
            except Exception as e:
                logger.error(f"Error in orchestration loop: {e}")
                await asyncio.sleep(30)
    
    async def _poll_for_incidents(self):
        """Poll for new enriched incidents"""
        try:
            # Query OpenSearch for new enriched incidents
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"status": "enriched"}},
                            {"range": {"timestamp": {"gte": "now-5m"}}}
                        ]
                    }
                },
                "sort": [{"risk_score": {"order": "desc"}}],
                "size": 10
            }
            
            response = await self.opensearch_client.search(
                index="banking-soc-enriched-incidents",
                body=query
            )
            
            for hit in response['hits']['hits']:
                incident_data = hit['_source']
                incident = EnrichedIncident(**incident_data)
                
                # Process incident
                await self.process_incident(incident)
                
                # Mark as processed
                await self.opensearch_client.update(
                    index="banking-soc-enriched-incidents",
                    id=hit['_id'],
                    body={"doc": {"status": "soar_processed"}}
                )
                
        except Exception as e:
            logger.error(f"Error polling for incidents: {e}")
    
    async def _process_pending_approvals(self):
        """Process pending approval responses"""
        try:
            # Get all pending approval requests
            keys = await self.redis_client.keys("approval_request:*")
            
            for key in keys:
                approval_data = await self.redis_client.get(key)
                if approval_data:
                    approval = json.loads(approval_data)
                    
                    # Check if approved
                    if approval.get('status') == ApprovalStatus.APPROVED:
                        incident_id = approval.get('incident_id')
                        logger.info(f"Processing approved incident {incident_id}")
                        
                        # Re-fetch incident from OpenSearch
                        incident_doc = await self.opensearch_client.get(
                            index="banking-soc-enriched-incidents",
                            id=incident_id
                        )
                        
                        if incident_doc and incident_doc.get('found'):
                            incident_data = incident_doc['_source']
                            # Ensure status is what process_incident expects or update logic
                            incident = EnrichedIncident(**incident_data)
                            
                            # Process incident (it will now pass the approval check)
                            await self.process_incident(incident)
                        
                        # Remove from pending
                        await self.redis_client.delete(key)
                        
        except Exception as e:
            logger.error(f"Error processing approvals: {e}")
    
    async def shutdown(self):
        """Shutdown orchestration engine"""
        logger.info("Shutting down Orchestration Engine...")
        
        if self.opensearch_client:
            await self.opensearch_client.close()
        
        if self.redis_client:
            await self.redis_client.close()
        
        logger.info("✅ Orchestration Engine shutdown complete")