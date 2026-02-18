#!/usr/bin/env python3
"""
OpenSearch ML Integration for Banking SOC
Integrates machine learning models for anomaly detection and behavioral analysis
"""

import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional

import requests
import urllib3
from opensearchpy import OpenSearch

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BankingSOCMLIntegration:
    def __init__(self):
        self.opensearch_url = os.getenv('OPENSEARCH_URL', 'https://localhost:9200')
        self.username = os.getenv('OPENSEARCH_USER', 'admin')
        self.password = os.getenv('OPENSEARCH_PASS', 'admin')
        
        # Initialize OpenSearch client
        self.client = OpenSearch(
            hosts=[{'host': 'localhost', 'port': 9200}],
            http_auth=(self.username, self.password),
            use_ssl=True,
            verify_certs=False,
            ssl_assert_hostname=False,
            ssl_show_warn=False
        )
    
    def wait_for_cluster(self) -> bool:
        """Wait for OpenSearch cluster to be ready"""
        max_retries = 30
        for i in range(max_retries):
            try:
                health = self.client.cluster.health()
                if health['status'] in ['yellow', 'green']:
                    logger.info(f"✅ OpenSearch cluster is ready: {health['status']}")
                    return True
            except Exception as e:
                logger.warning(f"Waiting for cluster (attempt {i+1}/{max_retries}): {e}")
                time.sleep(10)
        return False
    
    def create_banking_ml_models(self) -> bool:
        """Create and configure ML models for banking analytics"""
        try:
            # Anomaly detection model for transaction patterns
            transaction_anomaly_model = {
                "name": "banking_transaction_anomaly",
                "version": "1.0.0",
                "model_format": "TORCH_SCRIPT",
                "model_state": "TRAINED",
                "algorithm": "RCF",
                "description": "Random Cut Forest model for banking transaction anomaly detection",
                "model_config": {
                    "model_type": "rcf",
                    "embedding_dimension": 128,
                    "anomaly_rate": 0.005,
                    "time_decay": 0.0001,
                    "num_trees": 30,
                    "training_data_size": 256
                }
            }
            
            # User behavior analytics model
            user_behavior_model = {
                "name": "banking_user_behavior",
                "version": "1.0.0", 
                "model_format": "TORCH_SCRIPT",
                "model_state": "TRAINED",
                "algorithm": "ISOLATION_FOREST",
                "description": "Isolation Forest model for user behavioral analysis",
                "model_config": {
                    "model_type": "isolation_forest",
                    "contamination": 0.1,
                    "n_estimators": 100,
                    "max_samples": "auto",
                    "features": [
                        "login_frequency",
                        "transaction_volume", 
                        "geographic_variance",
                        "time_pattern_variance"
                    ]
                }
            }
            
            # Network traffic analysis model
            network_analysis_model = {
                "name": "banking_network_analysis",
                "version": "1.0.0",
                "model_format": "TORCH_SCRIPT", 
                "model_state": "TRAINED",
                "algorithm": "AUTOENCODER",
                "description": "Autoencoder for network traffic pattern analysis",
                "model_config": {
                    "model_type": "autoencoder",
                    "input_dimension": 50,
                    "encoding_dimension": 20,
                    "anomaly_threshold": 0.95,
                    "features": [
                        "bytes_in",
                        "bytes_out",
                        "packet_count",
                        "connection_duration",
                        "port_diversity"
                    ]
                }
            }
            
            models = [transaction_anomaly_model, user_behavior_model, network_analysis_model]
            
            for model in models:
                try:
                    response = self.client.transport.perform_request(
                        'POST',
                        '/_plugins/_ml/models/_register',
                        body=model
                    )
                    logger.info(f"✅ Registered ML model: {model['name']}")
                    
                    # Deploy the model
                    model_id = response.get('model_id')
                    if model_id:
                        deploy_response = self.client.transport.perform_request(
                            'POST',
                            f'/_plugins/_ml/models/{model_id}/_deploy'
                        )
                        logger.info(f"✅ Deployed ML model: {model['name']} (ID: {model_id})")
                        
                except Exception as e:
                    logger.error(f"❌ Failed to register model {model['name']}: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create ML models: {e}")
            return False
    
    def create_anomaly_detectors(self) -> bool:
        """Create anomaly detectors for banking use cases"""
        try:
            # Transaction volume anomaly detector
            transaction_detector = {
                "name": "banking_transaction_volume_detector",
                "description": "Detects anomalies in banking transaction volumes",
                "time_field": "@timestamp",
                "indices": ["banking-soc-logs-*"],
                "feature_attributes": [
                    {
                        "feature_name": "transaction_count",
                        "feature_enabled": True,
                        "aggregation_query": {
                            "transaction_count": {
                                "value_count": {
                                    "field": "transaction_amount"
                                }
                            }
                        }
                    },
                    {
                        "feature_name": "avg_transaction_amount", 
                        "feature_enabled": True,
                        "aggregation_query": {
                            "avg_transaction_amount": {
                                "avg": {
                                    "field": "transaction_amount"
                                }
                            }
                        }
                    }
                ],
                "detection_interval": {
                    "period": {
                        "interval": 5,
                        "unit": "Minutes"
                    }
                },
                "window_delay": {
                    "period": {
                        "interval": 1,
                        "unit": "Minutes"  
                    }
                }
            }
            
            # User login pattern detector
            login_detector = {
                "name": "banking_login_pattern_detector",
                "description": "Detects anomalous login patterns for banking users",
                "time_field": "@timestamp", 
                "indices": ["banking-soc-logs-*"],
                "filter_query": {
                    "bool": {
                        "must": [
                            {
                                "term": {
                                    "event_category": "api_access"
                                }
                            }
                        ]
                    }
                },
                "feature_attributes": [
                    {
                        "feature_name": "login_count",
                        "feature_enabled": True,
                        "aggregation_query": {
                            "login_count": {
                                "value_count": {
                                    "field": "user_id"
                                }
                            }
                        }
                    },
                    {
                        "feature_name": "unique_source_ips",
                        "feature_enabled": True,
                        "aggregation_query": {
                            "unique_source_ips": {
                                "cardinality": {
                                    "field": "source_ip"
                                }
                            }
                        }
                    }
                ],
                "detection_interval": {
                    "period": {
                        "interval": 10,
                        "unit": "Minutes"
                    }
                },
                "window_delay": {
                    "period": {
                        "interval": 1,
                        "unit": "Minutes"
                    }
                }
            }
            
            detectors = [transaction_detector, login_detector]
            
            for detector in detectors:
                try:
                    response = self.client.transport.perform_request(
                        'POST',
                        '/_plugins/_anomaly_detection/detectors',
                        body=detector
                    )
                    logger.info(f"✅ Created anomaly detector: {detector['name']}")
                    
                    # Start the detector
                    detector_id = response.get('_id')
                    if detector_id:
                        start_response = self.client.transport.perform_request(
                            'POST',
                            f'/_plugins/_anomaly_detection/detectors/{detector_id}/_start'
                        )
                        logger.info(f"✅ Started anomaly detector: {detector['name']}")
                        
                except Exception as e:
                    logger.error(f"❌ Failed to create detector {detector['name']}: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create anomaly detectors: {e}")
            return False
    
    def create_alerting_monitors(self) -> bool:
        """Create alerting monitors for banking security events"""
        try:
            # High-value transaction monitor
            high_value_monitor = {
                "name": "Banking High Value Transaction Alert",
                "type": "monitor",
                "enabled": True,
                "schedule": {
                    "period": {
                        "interval": 1,
                        "unit": "MINUTES"
                    }
                },
                "inputs": [
                    {
                        "search": {
                            "indices": ["banking-soc-logs-*"],
                            "query": {
                                "bool": {
                                    "filter": [
                                        {
                                            "range": {
                                                "@timestamp": {
                                                    "from": "{{period_end}}||-5m",
                                                    "to": "{{period_end}}",
                                                    "include_lower": True,
                                                    "include_upper": True
                                                }
                                            }
                                        },
                                        {
                                            "range": {
                                                "transaction_amount": {
                                                    "gte": 50000
                                                }
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    }
                ],
                "triggers": [
                    {
                        "name": "High Value Transaction Trigger",
                        "severity": "1",
                        "condition": {
                            "script": {
                                "source": "ctx.results[0].hits.total.value > 0"
                            }
                        },
                        "actions": [
                            {
                                "name": "Banking SOC Alert",
                                "destination_id": "",
                                "subject_template": {
                                    "source": "ALERT: High Value Transaction Detected"
                                },
                                "message_template": {
                                    "source": "High value transaction(s) detected. Count: {{ctx.results.0.hits.total.value}}"
                                }
                            }
                        ]
                    }
                ]
            }
            
            # Failed login monitor  
            failed_login_monitor = {
                "name": "Banking Failed Login Attempts",
                "type": "monitor",
                "enabled": True,
                "schedule": {
                    "period": {
                        "interval": 5,
                        "unit": "MINUTES"
                    }
                },
                "inputs": [
                    {
                        "search": {
                            "indices": ["banking-soc-logs-*"],
                            "query": {
                                "bool": {
                                    "filter": [
                                        {
                                            "range": {
                                                "@timestamp": {
                                                    "from": "{{period_end}}||-10m",
                                                    "to": "{{period_end}}"
                                                }
                                            }
                                        },
                                        {
                                            "terms": {
                                                "risk_flags": ["authentication_failure"]
                                            }
                                        }
                                    ]
                                }
                            },
                            "aggregations": {
                                "failed_logins_by_user": {
                                    "terms": {
                                        "field": "user_id",
                                        "size": 50
                                    }
                                }
                            }
                        }
                    }
                ],
                "triggers": [
                    {
                        "name": "Multiple Failed Logins",
                        "severity": "2", 
                        "condition": {
                            "script": {
                                "source": "ctx.results[0].aggregations.failed_logins_by_user.buckets.stream().anyMatch(bucket -> bucket.doc_count >= 5)"
                            }
                        },
                        "actions": [
                            {
                                "name": "Failed Login Alert",
                                "destination_id": "",
                                "subject_template": {
                                    "source": "ALERT: Multiple Failed Login Attempts"
                                },
                                "message_template": {
                                    "source": "Multiple failed login attempts detected for user(s). Review required."
                                }
                            }
                        ]
                    }
                ]
            }
            
            monitors = [high_value_monitor, failed_login_monitor]
            
            for monitor in monitors:
                try:
                    response = self.client.transport.perform_request(
                        'POST',
                        '/_plugins/_alerting/monitors',
                        body=monitor
                    )
                    logger.info(f"✅ Created alerting monitor: {monitor['name']}")
                    
                except Exception as e:
                    logger.error(f"❌ Failed to create monitor {monitor['name']}: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create alerting monitors: {e}")
            return False
    
    def setup_index_patterns_and_visualizations(self) -> bool:
        """Create OpenSearch Dashboards index patterns and basic visualizations"""
        try:
            # This would typically be done via the Dashboards API or manual configuration
            logger.info("ℹ️  Index patterns and visualizations should be configured via OpenSearch Dashboards UI")
            logger.info("   Recommended index patterns: banking-soc-logs-*, wazuh-alerts-*, banking-analytics-*")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to setup dashboards: {e}")
            return False
    
    def run_setup(self) -> bool:
        """Run the complete ML setup process"""
        logger.info("🚀 Starting Banking SOC ML Integration Setup")
        
        if not self.wait_for_cluster():
            logger.error("❌ OpenSearch cluster not ready")
            return False
        
        success = True
        
        # Setup ML models
        if not self.create_banking_ml_models():
            logger.error("❌ Failed to setup ML models")
            success = False
        
        # Setup anomaly detectors
        if not self.create_anomaly_detectors():
            logger.error("❌ Failed to setup anomaly detectors")
            success = False
        
        # Setup alerting monitors
        if not self.create_alerting_monitors():
            logger.error("❌ Failed to setup alerting monitors")
            success = False
        
        # Setup dashboards
        if not self.setup_index_patterns_and_visualizations():
            logger.error("❌ Failed to setup dashboards")
            success = False
        
        if success:
            logger.info("✅ Banking SOC ML Integration setup completed successfully")
        else:
            logger.error("❌ Banking SOC ML Integration setup completed with errors")
        
        return success

def main():
    """Main entry point"""
    ml_integration = BankingSOCMLIntegration()
    success = ml_integration.run_setup()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()