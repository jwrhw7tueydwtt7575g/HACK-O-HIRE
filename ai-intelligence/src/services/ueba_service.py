#!/usr/bin/env python3
"""
UEBA Service - User and Entity Behavior Analytics
Advanced behavioral modeling and risk scoring for banking SOC
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import json

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import networkx as nx
from py2neo import Graph

from core.config import Settings
from core.database import OpenSearchClient, RedisClient, Neo4jClient
from models.behavioral_models import UserBehaviorBaseline, EntityProfile, RiskScore
from utils.feature_engineering import BehavioralFeatureExtractor

logger = logging.getLogger(__name__)

class UEBAService:
    """
    User and Entity Behavior Analytics Service
    Implements advanced behavioral modeling and anomaly detection
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.opensearch_client = None
        self.redis_client = None
        self.neo4j_client = None
        self.feature_extractor = None
        self.isolation_forest = None
        self.scaler = StandardScaler()
        self.entity_baselines = {}
        self.user_baselines = {}
        
        # Model configuration
        self.model_config = {
            'isolation_forest': {
                'contamination': 0.1,
                'n_estimators': 100,
                'max_samples': 'auto',
                'random_state': 42
            },
            'dbscan': {
                'eps': 0.5,
                'min_samples': 5
            },
            'baseline_window_days': 30,
            'update_interval_hours': 6,
            'risk_threshold_high': 0.8,
            'risk_threshold_medium': 0.6
        }
    
    async def initialize(self):
        """Initialize the UEBA service"""
        logger.info("Initializing UEBA Service...")
        
        try:
            # Initialize data clients
            self.opensearch_client = OpenSearchClient(self.settings)
            await self.opensearch_client.connect()
            
            self.redis_client = RedisClient(self.settings)
            await self.redis_client.connect()
            
            self.neo4j_client = Neo4jClient(self.settings)
            await self.neo4j_client.connect()
            
            # Initialize feature extractor
            self.feature_extractor = BehavioralFeatureExtractor()
            
            # Load or train models
            await self.load_or_train_models()
            
            logger.info("✅ UEBA Service initialized successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize UEBA Service: {e}")
            raise
    
    async def load_or_train_models(self):
        """Load existing models or train new ones"""
        try:
            # Try to load existing model from Redis
            model_data = await self.redis_client.get('ueba_isolation_forest_model')
            
            if model_data:
                logger.info("Loading existing Isolation Forest model")
                # In production, implement proper model serialization
                self.isolation_forest = IsolationForest(**self.model_config['isolation_forest'])
            else:
                logger.info("Training new Isolation Forest model")
                await self.train_initial_models()
                
        except Exception as e:
            logger.error(f"Error loading/training models: {e}")
            # Fallback to new model
            self.isolation_forest = IsolationForest(**self.model_config['isolation_forest'])
    
    async def train_initial_models(self):
        """Train initial models with historical data"""
        logger.info("Training initial behavioral models...")
        
        try:
            # Get historical data for training
            end_time = datetime.now()
            start_time = end_time - timedelta(days=30)
            
            historical_data = await self.get_historical_behavioral_data(start_time, end_time)
            
            if len(historical_data) > 100:  # Minimum data requirement
                # Extract features for training
                features = self.feature_extractor.extract_training_features(historical_data)
                
                # Scale features
                features_scaled = self.scaler.fit_transform(features)
                
                # Train Isolation Forest
                self.isolation_forest.fit(features_scaled)
                
                # Save model to Redis (implement proper serialization in production)
                await self.redis_client.set('ueba_model_trained', str(datetime.now()))
                
                logger.info(f"✅ Models trained with {len(historical_data)} samples")
            else:
                logger.warning("Insufficient historical data for training, using default models")
                
        except Exception as e:
            logger.error(f"Error training initial models: {e}")
    
    async def get_historical_behavioral_data(self, start_time: datetime, end_time: datetime) -> pd.DataFrame:
        """Retrieve historical data for behavioral analysis"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": end_time.isoformat()
                                }
                            }
                        },
                        {
                            "terms": {
                                "event_category": ["banking_transaction", "api_access", "network_security"]
                            }
                        }
                    ]
                }
            },
            "size": 10000,
            "_source": [
                "@timestamp", "user_id", "source_ip", "transaction_amount", 
                "event_category", "privileged_operation", "after_hours",
                "geo_location", "user_agent", "account_id"
            ]
        }
        
        response = await self.opensearch_client.search(
            index="banking-soc-logs-*",
            body=query
        )
        
        hits = response['hits']['hits']
        data = [hit['_source'] for hit in hits]
        
        return pd.DataFrame(data)
    
    async def build_user_baseline(self, user_id: str) -> UserBehaviorBaseline:
        """Build behavioral baseline for a specific user"""
        try:
            # Get user's historical data (last 30 days)
            end_time = datetime.now()
            start_time = end_time - timedelta(days=self.model_config['baseline_window_days'])
            
            user_query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"user_id": user_id}},
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": start_time.isoformat(),
                                        "lte": end_time.isoformat()
                                    }
                                }
                            }
                        ]
                    }
                },
                "size": 5000
            }
            
            response = await self.opensearch_client.search(
                index="banking-soc-logs-*",
                body=user_query
            )
            
            if not response['hits']['hits']:
                logger.warning(f"No historical data found for user {user_id}")
                return None
            
            user_data = pd.DataFrame([hit['_source'] for hit in response['hits']['hits']])
            
            # Extract behavioral features
            features = self.feature_extractor.extract_user_features(user_data)
            
            # Build baseline
            baseline = UserBehaviorBaseline(
                user_id=user_id,
                login_patterns=self._analyze_login_patterns(user_data),
                transaction_patterns=self._analyze_transaction_patterns(user_data),
                geographical_patterns=self._analyze_geographical_patterns(user_data),
                time_patterns=self._analyze_time_patterns(user_data),
                access_patterns=self._analyze_access_patterns(user_data),
                baseline_created=datetime.now(),
                feature_statistics=features
            )
            
            # Store baseline in Redis
            await self.redis_client.set(
                f"user_baseline:{user_id}",
                baseline.to_json(),
                ex=86400 * 7  # 7 days TTL
            )
            
            self.user_baselines[user_id] = baseline
            
            logger.info(f"✅ Built baseline for user {user_id}")
            return baseline
            
        except Exception as e:
            logger.error(f"Error building baseline for user {user_id}: {e}")
            return None
    
    def _analyze_login_patterns(self, user_data: pd.DataFrame) -> Dict:
        """Analyze user login patterns"""
        login_data = user_data[user_data['event_category'] == 'api_access']
        
        if login_data.empty:
            return {}
        
        # Convert timestamp to datetime
        login_data['timestamp'] = pd.to_datetime(login_data['@timestamp'])
        login_data['hour'] = login_data['timestamp'].dt.hour
        login_data['day_of_week'] = login_data['timestamp'].dt.dayofweek
        
        return {
            'avg_logins_per_day': len(login_data) / 30,
            'peak_hours': login_data['hour'].mode().tolist(),
            'peak_days': login_data['day_of_week'].mode().tolist(),
            'unique_source_ips': login_data['source_ip'].nunique(),
            'common_user_agents': login_data['user_agent'].value_counts().head(3).to_dict()
        }
    
    def _analyze_transaction_patterns(self, user_data: pd.DataFrame) -> Dict:
        """Analyze user transaction patterns"""
        tx_data = user_data[user_data['event_category'] == 'banking_transaction']
        
        if tx_data.empty:
            return {}
        
        # Convert amounts to float, handle NaN values
        amounts = pd.to_numeric(tx_data['transaction_amount'], errors='coerce').dropna()
        
        if amounts.empty:
            return {}
        
        return {
            'avg_transaction_amount': amounts.mean(),
            'median_transaction_amount': amounts.median(),
            'std_transaction_amount': amounts.std(),
            'max_transaction_amount': amounts.max(),
            'transaction_frequency_per_day': len(tx_data) / 30,
            'large_transaction_threshold': amounts.quantile(0.95)
        }
    
    def _analyze_geographical_patterns(self, user_data: pd.DataFrame) -> Dict:
        """Analyze user geographical patterns"""
        geo_data = user_data[user_data['source_country'].notna()]
        
        if geo_data.empty:
            return {}
        
        return {
            'primary_countries': geo_data['source_country'].value_counts().head(3).to_dict(),
            'country_diversity': geo_data['source_country'].nunique(),
            'primary_asn': geo_data['source_asn'].mode().tolist() if 'source_asn' in geo_data else []
        }
    
    def _analyze_time_patterns(self, user_data: pd.DataFrame) -> Dict:
        """Analyze user time-based patterns"""
        user_data['timestamp'] = pd.to_datetime(user_data['@timestamp'])
        user_data['hour'] = user_data['timestamp'].dt.hour
        user_data['is_weekend'] = user_data['timestamp'].dt.dayofweek >= 5
        
        return {
            'active_hours_range': [user_data['hour'].min(), user_data['hour'].max()],
            'weekend_activity_ratio': user_data['is_weekend'].mean(),
            'after_hours_activity_ratio': user_data.get('after_hours', pd.Series()).mean() or 0,
            'activity_distribution_by_hour': user_data['hour'].value_counts().to_dict()
        }
    
    def _analyze_access_patterns(self, user_data: pd.DataFrame) -> Dict:
        """Analyze user access patterns"""
        return {
            'privileged_operation_ratio': user_data.get('privileged_operation', pd.Series()).mean() or 0,
            'unique_account_access': user_data['account_id'].nunique() if 'account_id' in user_data else 0,
            'event_category_distribution': user_data['event_category'].value_counts().to_dict()
        }
    
    async def analyze_current_behavior(self, user_id: str, current_events: List[Dict]) -> RiskScore:
        """Analyze current user behavior against baseline"""
        try:
            # Get or build user baseline
            baseline = self.user_baselines.get(user_id)
            if not baseline:
                baseline_data = await self.redis_client.get(f"user_baseline:{user_id}")
                if baseline_data:
                    baseline = UserBehaviorBaseline.from_json(baseline_data)
                    self.user_baselines[user_id] = baseline
                else:
                    baseline = await self.build_user_baseline(user_id)
            
            if not baseline:
                logger.warning(f"No baseline available for user {user_id}")
                return RiskScore(user_id=user_id, risk_score=0.5, confidence=0.1)
            
            # Extract features from current events
            current_features = self.feature_extractor.extract_current_features(current_events, baseline)
            
            # Calculate anomaly score using Isolation Forest
            if len(current_features) > 0:
                features_scaled = self.scaler.transform([current_features])
                anomaly_score = self.isolation_forest.decision_function(features_scaled)[0]
                
                # Convert to risk score (0-1 scale)
                risk_score = max(0, min(1, (1 - anomaly_score + 1) / 2))
            else:
                risk_score = 0.5
            
            # Calculate confidence based on baseline quality and data volume
            confidence = self._calculate_confidence(baseline, len(current_events))
            
            # Generate risk factors
            risk_factors = self._identify_risk_factors(current_events, baseline)
            
            result = RiskScore(
                user_id=user_id,
                risk_score=risk_score,
                confidence=confidence,
                risk_factors=risk_factors,
                analysis_timestamp=datetime.now(),
                model_version="1.0.0"
            )
            
            # Store result for trending
            await self.redis_client.zadd(
                f"user_risk_history:{user_id}",
                {datetime.now().timestamp(): risk_score}
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing behavior for user {user_id}: {e}")
            return RiskScore(user_id=user_id, risk_score=0.5, confidence=0.1)
    
    def _calculate_confidence(self, baseline: UserBehaviorBaseline, current_event_count: int) -> float:
        """Calculate confidence score for the risk assessment"""
        # Factors that affect confidence:
        # 1. Age of baseline
        # 2. Amount of historical data
        # 3. Amount of current data
        # 4. Consistency of baseline
        
        age_factor = 1.0
        if baseline.baseline_created:
            days_old = (datetime.now() - baseline.baseline_created).days
            age_factor = max(0.1, 1.0 - (days_old / 30))  # Decay over 30 days
        
        data_factor = min(1.0, current_event_count / 10)  # More events = higher confidence
        
        return (age_factor + data_factor) / 2
    
    def _identify_risk_factors(self, current_events: List[Dict], baseline: UserBehaviorBaseline) -> List[str]:
        """Identify specific risk factors in current behavior"""
        risk_factors = []
        
        for event in current_events:
            # Check for geographical anomalies
            if event.get('source_country') not in baseline.geographical_patterns.get('primary_countries', {}):
                risk_factors.append("unusual_geographical_location")
            
            # Check for time anomalies
            event_hour = pd.to_datetime(event.get('@timestamp')).hour
            if event_hour not in baseline.time_patterns.get('active_hours_range', [0, 23]):
                risk_factors.append("unusual_access_time")
            
            # Check for transaction amount anomalies
            if event.get('transaction_amount'):
                amount = float(event['transaction_amount'])
                threshold = baseline.transaction_patterns.get('large_transaction_threshold', 0)
                if amount > threshold:
                    risk_factors.append("unusually_large_transaction")
            
            # Check for privileged operations
            if event.get('privileged_operation'):
                baseline_priv_ratio = baseline.access_patterns.get('privileged_operation_ratio', 0)
                if baseline_priv_ratio < 0.1:  # User rarely does privileged ops
                    risk_factors.append("unexpected_privileged_access")
        
        return list(set(risk_factors))  # Remove duplicates
    
    async def start_processing(self):
        """Start the main UEBA processing loop"""
        logger.info("🔄 Starting UEBA processing loop...")
        
        while True:
            try:
                # Process recent events for behavioral analysis
                await self._process_recent_events()
                
                # Update baselines periodically
                await self._update_baselines()
                
                # Sleep before next iteration
                await asyncio.sleep(300)  # 5 minutes
                
            except asyncio.CancelledError:
                logger.info("UEBA processing cancelled")
                break
            except Exception as e:
                logger.error(f"Error in UEBA processing loop: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _process_recent_events(self):
        """Process recent events for behavioral analysis"""
        try:
            # Get events from last 5 minutes
            end_time = datetime.now()
            start_time = end_time - timedelta(minutes=5)
            
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat()
                        }
                    }
                },
                "size": 1000
            }
            
            response = await self.opensearch_client.search(
                index="banking-soc-logs-*",
                body=query
            )
            
            events = [hit['_source'] for hit in response['hits']['hits']]
            
            # Group events by user
            user_events = {}
            for event in events:
                user_id = event.get('user_id')
                if user_id:
                    if user_id not in user_events:
                        user_events[user_id] = []
                    user_events[user_id].append(event)
            
            # Analyze each user's behavior
            for user_id, events in user_events.items():
                try:
                    risk_score = await self.analyze_current_behavior(user_id, events)
                    
                    # If high risk, create alert
                    if risk_score.risk_score > self.model_config['risk_threshold_high']:
                        await self._create_risk_alert(risk_score, events)
                except Exception as user_e:
                    logger.error(f"Error analyzing behavior for user {user_id}: {user_e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error processing recent events: {e}")
    
    async def _update_baselines(self):
        """Update user baselines periodically"""
        try:
            # Get list of active users from recent activity
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=self.model_config['update_interval_hours'])
            
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat()
                        }
                    }
                },
                "aggs": {
                    "active_users": {
                        "terms": {
                            "field": "user_id",
                            "size": 100
                        }
                    }
                },
                "size": 0
            }
            
            response = await self.opensearch_client.search(
                index="banking-soc-logs-*",
                body=query
            )
            
            active_users = [bucket['key'] for bucket in response['aggregations']['active_users']['buckets']]
            
            # Update baselines for active users
            for user_id in active_users:
                try:
                    await self.build_user_baseline(user_id)
                except Exception as e:
                    logger.error(f"Error updating baseline for user {user_id}: {e}")
                    
        except Exception as e:
            logger.error(f"Error updating baselines: {e}")
    
    async def _create_risk_alert(self, risk_score: RiskScore, events: List[Dict]):
        """Create a high-risk behavior alert"""
        alert = {
            "@timestamp": datetime.now().isoformat(),
            "alert_type": "ueba_high_risk_behavior",
            "user_id": risk_score.user_id,
            "risk_score": risk_score.risk_score,
            "confidence": risk_score.confidence,
            "risk_factors": risk_score.risk_factors,
            "event_count": len(events),
            "severity": "HIGH" if risk_score.risk_score > 0.9 else "MEDIUM"
        }
        
        # Send to OpenSearch alerts index
        await self.opensearch_client.index(
            index="banking-analytics-alerts",
            body=alert
        )
        
        logger.warning(f"🚨 High risk behavior detected for user {risk_score.user_id} (score: {risk_score.risk_score:.2f})")
    
    async def shutdown(self):
        """Gracefully shutdown the UEBA service"""
        logger.info("Shutting down UEBA Service...")
        
        if self.opensearch_client:
            await self.opensearch_client.close()
        
        if self.redis_client:
            await self.redis_client.close()
        
        if self.neo4j_client:
            await self.neo4j_client.close()
        
        logger.info("✅ UEBA Service shutdown complete")