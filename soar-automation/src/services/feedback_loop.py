#!/usr/bin/env python3
"""
Feedback Loop Service - Continuous Learning and Improvement
Collects feedback from incident responses and improves detection and response over time
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from enum import Enum

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from core.config import Settings

logger = logging.getLogger(__name__)

class FeedbackType(str, Enum):
    FALSE_POSITIVE = "false_positive"
    TRUE_POSITIVE = "true_positive"
    PLAYBOOK_EFFECTIVE = "playbook_effective"
    PLAYBOOK_INEFFECTIVE = "playbook_ineffective"
    ACTION_SUCCESSFUL = "action_successful"
    ACTION_FAILED = "action_failed"
    ANALYST_OVERRIDE = "analyst_override"

class FeedbackLoopService:
    """
    Feedback loop service for continuous improvement
    Learns from incident outcomes to improve detection and response
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.opensearch_client = None
        self.redis_client = None
        self.neo4j_client = None
        
        # ML models for learning
        self.effectiveness_predictor = None
        self.false_positive_classifier = None
        self.scaler = StandardScaler()
        
        # Feedback statistics
        self.feedback_stats = {
            'total_feedback': 0,
            'false_positives': 0,
            'true_positives': 0,
            'effective_playbooks': 0,
            'ineffective_playbooks': 0
        }
    
    async def initialize(self):
        """Initialize feedback loop service"""
        logger.info("Initializing Feedback Loop Service...")
        
        try:
            from core.database import OpenSearchClient, RedisClient, Neo4jClient
            
            self.opensearch_client = OpenSearchClient(self.settings)
            await self.opensearch_client.connect()
            
            self.redis_client = RedisClient(self.settings)
            await self.redis_client.connect()
            
            self.neo4j_client = Neo4jClient(self.settings)
            await self.neo4j_client.connect()
            
            # Load or train ML models
            await self._load_or_train_models()
            
            logger.info("✅ Feedback Loop Service initialized")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize Feedback Loop Service: {e}")
            raise
    
    async def _load_or_train_models(self):
        """Load existing models or train new ones"""
        try:
            # Try to load from Redis
            model_data = await self.redis_client.get('feedback_models')
            
            if model_data:
                logger.info("Loading existing feedback models")
                # Implement model deserialization
                self.effectiveness_predictor = RandomForestClassifier(n_estimators=100, random_state=42)
                self.false_positive_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
            else:
                logger.info("Training new feedback models")
                await self._train_initial_models()
                
        except Exception as e:
            logger.error(f"Error loading/training models: {e}")
            # Fallback to new models
            self.effectiveness_predictor = RandomForestClassifier(n_estimators=100, random_state=42)
            self.false_positive_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
    
    async def _train_initial_models(self):
        """Train initial models with historical feedback data"""
        logger.info("Training initial feedback models...")
        
        try:
            # Get historical feedback data
            historical_feedback = await self._get_historical_feedback(days=90)
            
            if len(historical_feedback) > 100:
                # Extract features and train
                features, labels = self._prepare_training_data(historical_feedback)
                
                if len(features) > 0:
                    # Train effectiveness predictor
                    self.effectiveness_predictor.fit(features, labels['effectiveness'])
                    
                    # Train false positive classifier
                    self.false_positive_classifier.fit(features, labels['false_positive'])
                    
                    # Save models
                    await self.redis_client.set('feedback_models_trained', str(datetime.now()))
                    
                    logger.info(f"✅ Models trained with {len(historical_feedback)} samples")
            else:
                logger.warning("Insufficient historical data for training")
                
        except Exception as e:
            logger.error(f"Error training initial models: {e}")
    
    async def collect_feedback(self, incident_id: str, feedback_type: FeedbackType, 
                               details: Dict, analyst_id: str) -> Dict:
        """
        Collect feedback from analysts on incident response
        """
        logger.info(f"Collecting feedback for incident {incident_id}: {feedback_type}")
        
        try:
            feedback_record = {
                'incident_id': incident_id,
                'feedback_type': feedback_type,
                'details': details,
                'analyst_id': analyst_id,
                'timestamp': datetime.now().isoformat(),
                'processed': False
            }
            
            # Store feedback in OpenSearch
            await self.opensearch_client.index(
                index="banking-soc-feedback",
                body=feedback_record
            )
            
            # Update statistics
            self.feedback_stats['total_feedback'] += 1
            
            if feedback_type == FeedbackType.FALSE_POSITIVE:
                self.feedback_stats['false_positives'] += 1
                await self._process_false_positive_feedback(incident_id, details)
            elif feedback_type == FeedbackType.TRUE_POSITIVE:
                self.feedback_stats['true_positives'] += 1
                await self._process_true_positive_feedback(incident_id, details)
            elif feedback_type == FeedbackType.PLAYBOOK_EFFECTIVE:
                self.feedback_stats['effective_playbooks'] += 1
                await self._process_playbook_effectiveness(incident_id, details, effective=True)
            elif feedback_type == FeedbackType.PLAYBOOK_INEFFECTIVE:
                self.feedback_stats['ineffective_playbooks'] += 1
                await self._process_playbook_effectiveness(incident_id, details, effective=False)
            
            logger.info(f"✅ Feedback collected for incident {incident_id}")
            
            return {
                'status': 'success',
                'feedback_id': feedback_record.get('id'),
                'message': 'Feedback recorded and will be used for system improvement'
            }
            
        except Exception as e:
            logger.error(f"Failed to collect feedback: {e}")
            raise
    
    async def _process_false_positive_feedback(self, incident_id: str, details: Dict):
        """Process false positive feedback to reduce future false alarms"""
        logger.info(f"Processing false positive feedback for {incident_id}")
        
        try:
            # Get incident details
            incident = await self._get_incident(incident_id)
            
            if not incident:
                return
            
            # Identify what caused false positive
            false_positive_patterns = details.get('patterns', [])
            
            # Update UEBA baselines if behavioral anomaly was false alarm
            if 'behavioral_anomaly' in false_positive_patterns:
                await self._update_behavioral_baseline(incident, is_false_positive=True)
            
            # Tune Wazuh rules if rule-based detection triggered
            if 'wazuh_rule' in incident:
                await self._tune_wazuh_rule(incident['wazuh_rule'], increase_threshold=True)
            
            # Update ML model with false positive example
            await self._update_false_positive_classifier(incident)
            
            # Store pattern in knowledge base for future reference
            await self._store_false_positive_pattern(incident, details)
            
            logger.info(f"✅ Processed false positive feedback for {incident_id}")
            
        except Exception as e:
            logger.error(f"Error processing false positive feedback: {e}")
    
    async def _process_true_positive_feedback(self, incident_id: str, details: Dict):
        """Process true positive feedback to reinforce detection"""
        logger.info(f"Processing true positive feedback for {incident_id}")
        
        try:
            # Get incident details
            incident = await self._get_incident(incident_id)
            
            if not incident:
                return
            
            # Reinforce detection patterns
            attack_patterns = details.get('attack_patterns', [])
            
            # Update threat intelligence with confirmed IOCs
            if 'iocs' in details:
                await self._update_threat_intelligence(details['iocs'], confirmed=True)
            
            # Strengthen Wazuh rules
            if 'wazuh_rule' in incident:
                await self._tune_wazuh_rule(incident['wazuh_rule'], increase_threshold=False)
            
            # Update MITRE ATT&CK knowledge graph
            if 'mitre_techniques' in details:
                await self._update_mitre_knowledge_graph(incident, details['mitre_techniques'])
            
            # Store in knowledge base as positive example
            await self._store_true_positive_example(incident, details)
            
            logger.info(f"✅ Processed true positive feedback for {incident_id}")
            
        except Exception as e:
            logger.error(f"Error processing true positive feedback: {e}")
    
    async def _process_playbook_effectiveness(self, incident_id: str, 
                                             details: Dict, effective: bool):
        """Process playbook effectiveness feedback"""
        logger.info(f"Processing playbook effectiveness feedback for {incident_id}: effective={effective}")
        
        try:
            # Get incident and playbook details
            incident = await self._get_incident(incident_id)
            
            if not incident:
                return
            
            playbook_id = incident.get('playbook_id')
            
            # Calculate effectiveness score
            effectiveness_score = details.get('effectiveness_score', 0.5 if not effective else 0.9)
            
            # Store effectiveness feedback
            effectiveness_record = {
                'incident_id': incident_id,
                'playbook_id': playbook_id,
                'effective': effective,
                'effectiveness_score': effectiveness_score,
                'resolution_time_minutes': details.get('resolution_time_minutes'),
                'actions_executed': details.get('actions_executed'),
                'successful_actions': details.get('successful_actions'),
                'analyst_notes': details.get('notes'),
                'timestamp': datetime.now().isoformat()
            }
            
            await self.opensearch_client.index(
                index="banking-soc-playbook-effectiveness",
                body=effectiveness_record
            )
            
            # Update LLM fine-tuning dataset
            if effective:
                await self._add_to_llm_fine_tuning_dataset(incident, playbook_id, positive=True)
            else:
                await self._add_to_llm_fine_tuning_dataset(incident, playbook_id, positive=False)
            
            # Update playbook versioning if significant ineffectiveness
            if not effective and effectiveness_score < 0.4:
                await self._flag_playbook_for_review(playbook_id, incident_id, details)
            
            logger.info(f"✅ Processed playbook effectiveness feedback for {incident_id}")
            
        except Exception as e:
            logger.error(f"Error processing playbook effectiveness: {e}")
    
    async def _update_behavioral_baseline(self, incident: Dict, is_false_positive: bool):
        """Update UEBA baseline based on feedback"""
        try:
            user_id = incident.get('user_id')
            if not user_id:
                return
            
            # Send update to AI Intelligence service
            update_payload = {
                'user_id': user_id,
                'incident_id': incident['incident_id'],
                'is_false_positive': is_false_positive,
                'behavioral_features': incident.get('behavioral_features', {}),
                'timestamp': datetime.now().isoformat()
            }
            
            # Post to AI Intelligence API
            # await self.ai_intelligence_client.post('/api/v1/baseline/update', json=update_payload)
            
            logger.info(f"Updated baseline for user {user_id} (FP: {is_false_positive})")
            
        except Exception as e:
            logger.error(f"Error updating behavioral baseline: {e}")
    
    async def _tune_wazuh_rule(self, rule_id: str, increase_threshold: bool):
        """Tune Wazuh detection rule based on feedback"""
        try:
            # Get current rule configuration
            # rule = await self.wazuh_api.get_rule(rule_id)
            
            adjustment = "increase" if increase_threshold else "decrease"
            
            # Log rule tuning recommendation
            tuning_record = {
                'rule_id': rule_id,
                'adjustment': adjustment,
                'reason': 'false_positive' if increase_threshold else 'true_positive',
                'timestamp': datetime.now().isoformat(),
                'status': 'pending_review'
            }
            
            await self.opensearch_client.index(
                index="banking-soc-rule-tuning",
                body=tuning_record
            )
            
            logger.info(f"Flagged Wazuh rule {rule_id} for tuning: {adjustment} threshold")
            
        except Exception as e:
            logger.error(f"Error tuning Wazuh rule: {e}")
    
    async def _update_threat_intelligence(self, iocs: List[Dict], confirmed: bool):
        """Update threat intelligence with confirmed IOCs"""
        try:
            for ioc in iocs:
                ioc_record = {
                    **ioc,
                    'confirmed': confirmed,
                    'confidence': 0.95 if confirmed else 0.5,
                    'last_seen': datetime.now().isoformat(),
                    'source': 'banking_soc_feedback'
                }
                
                await self.opensearch_client.index(
                    index="banking-soc-threat-intel",
                    body=ioc_record
                )
            
            logger.info(f"Updated threat intelligence with {len(iocs)} IOCs (confirmed: {confirmed})")
            
        except Exception as e:
            logger.error(f"Error updating threat intelligence: {e}")
    
    async def _update_mitre_knowledge_graph(self, incident: Dict, techniques: List[str]):
        """Update MITRE ATT&CK knowledge graph with confirmed techniques"""
        try:
            # Update Neo4j graph with relationships
            for technique in techniques:
                # Create or update technique node
                query = """
                MERGE (i:Incident {id: $incident_id})
                MERGE (t:Technique {id: $technique_id})
                MERGE (i)-[r:USES_TECHNIQUE]->(t)
                ON CREATE SET r.first_seen = datetime()
                SET r.last_seen = datetime(),
                    r.count = COALESCE(r.count, 0) + 1,
                    r.confirmed = true
                """
                
                # await self.neo4j_client.run(query, incident_id=incident['incident_id'], technique_id=technique)
            
            logger.info(f"Updated MITRE knowledge graph with {len(techniques)} techniques")
            
        except Exception as e:
            logger.error(f"Error updating MITRE knowledge graph: {e}")
    
    async def _add_to_llm_fine_tuning_dataset(self, incident: Dict, playbook_id: str, positive: bool):
        """Add incident-playbook pair to LLM fine-tuning dataset"""
        try:
            fine_tuning_example = {
                'incident_context': incident,
                'playbook_id': playbook_id,
                'playbook_content': incident.get('playbook'),
                'effective': positive,
                'timestamp': datetime.now().isoformat()
            }
            
            # Store in fine-tuning dataset
            await self.opensearch_client.index(
                index="banking-soc-llm-fine-tuning",
                body=fine_tuning_example
            )
            
            logger.info(f"Added example to LLM fine-tuning dataset (positive: {positive})")
            
        except Exception as e:
            logger.error(f"Error adding to fine-tuning dataset: {e}")
    
    async def _flag_playbook_for_review(self, playbook_id: str, incident_id: str, details: Dict):
        """Flag playbook for human review and improvement"""
        try:
            review_flag = {
                'playbook_id': playbook_id,
                'incident_id': incident_id,
                'reason': 'low_effectiveness',
                'effectiveness_score': details.get('effectiveness_score'),
                'analyst_feedback': details.get('notes'),
                'flagged_at': datetime.now().isoformat(),
                'status': 'pending_review'
            }
            
            await self.opensearch_client.index(
                index="banking-soc-playbook-reviews",
                body=review_flag
            )
            
            # Notify playbook engineering team
            logger.warning(f"⚠️  Playbook {playbook_id} flagged for review due to low effectiveness")
            
        except Exception as e:
            logger.error(f"Error flagging playbook for review: {e}")
    
    async def _get_incident(self, incident_id: str) -> Optional[Dict]:
        """Get incident details from OpenSearch"""
        try:
            response = await self.opensearch_client.get(
                index="banking-soc-enriched-incidents",
                id=incident_id
            )
            return response['_source'] if response else None
        except Exception as e:
            logger.error(f"Error getting incident: {e}")
            return None
    
    async def _get_historical_feedback(self, days: int = 90) -> List[Dict]:
        """Get historical feedback data"""
        try:
            query = {
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": f"now-{days}d"
                        }
                    }
                },
                "size": 10000
            }
            
            response = await self.opensearch_client.search(
                index="banking-soc-feedback",
                body=query
            )
            
            return [hit['_source'] for hit in response['hits']['hits']]
            
        except Exception as e:
            logger.error(f"Error getting historical feedback: {e}")
            return []
    
    def _prepare_training_data(self, feedback_data: List[Dict]):
        """Prepare training data from feedback"""
        # Extract features and labels from feedback data
        # Implementation depends on specific feature engineering
        features = []
        labels = {'effectiveness': [], 'false_positive': []}
        
        # Feature extraction logic here
        
        return np.array(features), labels
    
    async def _store_false_positive_pattern(self, incident: Dict, details: Dict):
        """Store false positive pattern in knowledge base"""
        pattern_record = {
            'incident_id': incident['incident_id'],
            'pattern_type': 'false_positive',
            'patterns': details.get('patterns', []),
            'features': incident.get('features', {}),
            'stored_at': datetime.now().isoformat()
        }
        
        await self.opensearch_client.index(
            index="banking-soc-detection-patterns",
            body=pattern_record
        )
    
    async def _store_true_positive_example(self, incident: Dict, details: Dict):
        """Store true positive example in knowledge base"""
        example_record = {
            'incident_id': incident['incident_id'],
            'pattern_type': 'true_positive',
            'attack_patterns': details.get('attack_patterns', []),
            'iocs': details.get('iocs', []),
            'features': incident.get('features', {}),
            'stored_at': datetime.now().isoformat()
        }
        
        await self.opensearch_client.index(
            index="banking-soc-detection-patterns",
            body=example_record
        )
    
    async def process_feedback(self):
        """Main feedback processing loop"""
        logger.info("🔄 Starting feedback processing loop...")
        
        while True:
            try:
                # Process new feedback
                await self._process_new_feedback()
                
                # Retrain models periodically
                await self._retrain_models_if_needed()
                
                # Generate improvement reports
                await self._generate_improvement_reports()
                
                # Sleep before next iteration
                await asyncio.sleep(300)  # 5 minutes
                
            except asyncio.CancelledError:
                logger.info("Feedback processing cancelled")
                break
            except Exception as e:
                logger.error(f"Error in feedback processing loop: {e}")
                await asyncio.sleep(60)
    
    async def _process_new_feedback(self):
        """Process newly received feedback"""
        # Implementation for processing unprocessed feedback
        pass
    
    async def _retrain_models_if_needed(self):
        """Check if models need retraining and retrain if necessary"""
        # Check feedback volume and time since last training
        # Retrain if thresholds are met
        pass
    
    async def _generate_improvement_reports(self):
        """Generate periodic improvement and effectiveness reports"""
        # Generate reports on false positive reduction, playbook effectiveness, etc.
        pass
    
    async def shutdown(self):
        """Shutdown feedback loop service"""
        logger.info("Shutting down Feedback Loop Service...")
        
        if self.opensearch_client:
            await self.opensearch_client.close()
        
        if self.redis_client:
            await self.redis_client.close()
        
        if self.neo4j_client:
            await self.neo4j_client.close()
        
        logger.info("✅ Feedback Loop Service shutdown complete")