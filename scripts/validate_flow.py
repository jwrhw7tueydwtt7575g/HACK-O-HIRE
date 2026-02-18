#!/usr/bin/env python3
"""
End-to-End Flow Validation Script
Tests complete data flow from log generation to SOAR execution
"""

import asyncio
import json
import time
import requests
from datetime import datetime
from typing import Dict, List
import sys

class FlowValidator:
    """Validates complete SOC pipeline flow"""
    
    def __init__(self):
        self.services = {
            'opensearch': 'http://localhost:9200',
            'vector': 'http://localhost:8686',
            'wazuh': 'https://localhost:55000',
            'ai_intelligence': 'http://localhost:8001',
            'enrichment': 'http://localhost:8002',
            'soar': 'http://localhost:8003',
            'neo4j': 'http://localhost:7474',
            'grafana': 'http://localhost:3000',
        }
        
        self.test_results = {}
        
    def print_header(self, text: str):
        """Print formatted header"""
        print(f"\n{'='*70}")
        print(f"  {text}")
        print(f"{'='*70}\n")
    
    def print_status(self, service: str, status: str, message: str = ""):
        """Print service status"""
        symbol = "✅" if status == "OK" else "❌"
        print(f"{symbol} {service:25} [{status}] {message}")
    
    async def check_service_health(self, service_name: str, url: str) -> bool:
        """Check if service is healthy"""
        try:
            response = requests.get(f"{url}/health", timeout=5, verify=False)
            if response.status_code == 200:
                self.print_status(service_name, "OK", "Service is healthy")
                return True
            else:
                self.print_status(service_name, "WARN", f"Status: {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            self.print_status(service_name, "DOWN", "Cannot connect")
            return False
        except Exception as e:
            self.print_status(service_name, "ERROR", str(e))
            return False
    
    async def check_opensearch(self) -> bool:
        """Check OpenSearch cluster health"""
        try:
            response = requests.get(
                f"{self.services['opensearch']}/_cluster/health",
                auth=('admin', 'Admin123!@#'),
                verify=False,
                timeout=5
            )
            
            if response.status_code == 200:
                health = response.json()
                status = health.get('status', 'unknown')
                
                if status in ['green', 'yellow']:
                    self.print_status("OpenSearch", "OK", f"Cluster: {status}")
                    
                    # Check indices
                    indices_response = requests.get(
                        f"{self.services['opensearch']}/_cat/indices?format=json",
                        auth=('admin', 'Admin123!@#'),
                        verify=False
                    )
                    
                    if indices_response.status_code == 200:
                        indices = indices_response.json()
                        banking_indices = [i for i in indices if 'banking-soc' in i.get('index', '')]
                        print(f"   📊 Found {len(banking_indices)} banking-soc indices")
                        for idx in banking_indices[:5]:
                            print(f"      - {idx['index']}: {idx.get('docs.count', 0)} docs")
                    
                    return True
                else:
                    self.print_status("OpenSearch", "WARN", f"Cluster: {status}")
                    return False
            else:
                self.print_status("OpenSearch", "ERROR", f"HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.print_status("OpenSearch", "ERROR", str(e))
            return False
    
    async def check_vector_metrics(self) -> bool:
        """Check Vector pipeline metrics"""
        try:
            response = requests.get(
                f"{self.services['vector']}/metrics",
                timeout=5
            )
            
            if response.status_code == 200:
                metrics = response.text
                
                # Parse key metrics
                events_in = 0
                events_out = 0
                
                for line in metrics.split('\n'):
                    if 'component_received_events_total' in line and not line.startswith('#'):
                        try:
                            events_in += float(line.split()[-1])
                        except:
                            pass
                    if 'component_sent_events_total' in line and not line.startswith('#'):
                        try:
                            events_out += float(line.split()[-1])
                        except:
                            pass
                
                self.print_status("Vector Pipeline", "OK", f"In: {int(events_in)}, Out: {int(events_out)}")
                return True
            else:
                self.print_status("Vector Pipeline", "WARN", "Cannot fetch metrics")
                return False
                
        except Exception as e:
            self.print_status("Vector Pipeline", "ERROR", str(e))
            return False
    
    async def test_log_ingestion(self) -> bool:
        """Test log ingestion through Vector"""
        try:
            self.print_header("Testing Log Ingestion")
            
            # Send test log to Vector
            test_log = {
                "timestamp": datetime.now().isoformat(),
                "source": "test_validation",
                "event_category": "test",
                "message": "E2E validation test log",
                "severity": "info",
                "test_id": f"test_{int(time.time())}"
            }
            
            response = requests.post(
                f"http://localhost:8080/api/logs",
                json=test_log,
                timeout=5
            )
            
            if response.status_code in [200, 201, 202]:
                self.print_status("Log Ingestion", "OK", "Test log accepted")
                
                # Wait for processing
                await asyncio.sleep(5)
                
                # Check if log reached OpenSearch
                search_response = requests.get(
                    f"{self.services['opensearch']}/banking-soc-logs-*/_search",
                    auth=('admin', 'Admin123!@#'),
                    verify=False,
                    json={
                        "query": {
                            "match": {"test_id": test_log["test_id"]}
                        }
                    }
                )
                
                if search_response.status_code == 200:
                    hits = search_response.json().get('hits', {}).get('total', {}).get('value', 0)
                    if hits > 0:
                        self.print_status("Log in OpenSearch", "OK", f"Found {hits} matching logs")
                        return True
                    else:
                        self.print_status("Log in OpenSearch", "WARN", "Log not found yet")
                        return False
            else:
                self.print_status("Log Ingestion", "ERROR", f"HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.print_status("Log Ingestion", "ERROR", str(e))
            return False
    
    async def test_incident_flow(self) -> bool:
        """Test incident processing flow"""
        try:
            self.print_header("Testing Incident Processing Flow")
            
            # Create test incident
            test_incident = {
                "incident_id": f"INC-TEST-{int(time.time())}",
                "timestamp": datetime.now().isoformat(),
                "source": "wazuh",
                "severity": "high",
                "status": "new",
                "confidence": 0.85,
                "risk_score": 75.0,
                "title": "Test Security Incident",
                "description": "E2E validation test incident",
                "affected_assets": ["test-server-01"],
                "attack_techniques": ["T1078"],
                "original_alerts": [],
                "raw_logs": []
            }
            
            # Insert into OpenSearch
            response = requests.post(
                f"{self.services['opensearch']}/banking-soc-incidents/_doc",
                auth=('admin', 'Admin123!@#'),
                verify=False,
                json=test_incident
            )
            
            if response.status_code in [200, 201]:
                self.print_status("Incident Created", "OK", test_incident['incident_id'])
                
                # Wait for enrichment
                print("   ⏳ Waiting for enrichment (30s)...")
                await asyncio.sleep(30)
                
                # Check enriched incident
                enriched_response = requests.get(
                    f"{self.services['opensearch']}/banking-soc-incidents-enriched/_search",
                    auth=('admin', 'Admin123!@#'),
                    verify=False,
                    json={
                        "query": {
                            "match": {"incident_id": test_incident["incident_id"]}
                        }
                    }
                )
                
                if enriched_response.status_code == 200:
                    hits = enriched_response.json().get('hits', {}).get('total', {}).get('value', 0)
                    if hits > 0:
                        self.print_status("Incident Enriched", "OK", "Enrichment complete")
                        
                        # Check for playbook
                        playbook_response = requests.get(
                            f"{self.services['opensearch']}/banking-soc-playbooks/_search",
                            auth=('admin', 'Admin123!@#'),
                            verify=False,
                            json={
                                "query": {
                                    "match": {"incident_id": test_incident["incident_id"]}
                                }
                            }
                        )
                        
                        if playbook_response.status_code == 200:
                            pb_hits = playbook_response.json().get('hits', {}).get('total', {}).get('value', 0)
                            if pb_hits > 0:
                                self.print_status("Playbook Generated", "OK", "LLM playbook created")
                                return True
                            else:
                                self.print_status("Playbook Generated", "PENDING", "Not yet generated")
                                return False
                    else:
                        self.print_status("Incident Enriched", "PENDING", "Not yet enriched")
                        return False
            else:
                self.print_status("Incident Created", "ERROR", f"HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.print_status("Incident Flow", "ERROR", str(e))
            return False
    
    async def check_data_flow_metrics(self):
        """Check data flow metrics across pipeline"""
        try:
            self.print_header("Data Flow Metrics")
            
            # Check log volume
            logs_response = requests.get(
                f"{self.services['opensearch']}/banking-soc-logs-*/_count",
                auth=('admin', 'Admin123!@#'),
                verify=False
            )
            
            if logs_response.status_code == 200:
                log_count = logs_response.json().get('count', 0)
                print(f"   📊 Total Logs: {log_count:,}")
            
            # Check incidents
            incidents_response = requests.get(
                f"{self.services['opensearch']}/banking-soc-incidents/_count",
                auth=('admin', 'Admin123!@#'),
                verify=False
            )
            
            if incidents_response.status_code == 200:
                incident_count = incidents_response.json().get('count', 0)
                print(f"   🚨 Total Incidents: {incident_count:,}")
            
            # Check enriched incidents
            enriched_response = requests.get(
                f"{self.services['opensearch']}/banking-soc-incidents-enriched/_count",
                auth=('admin', 'Admin123!@#'),
                verify=False
            )
            
            if enriched_response.status_code == 200:
                enriched_count = enriched_response.json().get('count', 0)
                print(f"   🎯 Enriched Incidents: {enriched_count:,}")
            
            # Check playbooks
            playbook_response = requests.get(
                f"{self.services['opensearch']}/banking-soc-playbooks/_count",
                auth=('admin', 'Admin123!@#'),
                verify=False
            )
            
            if playbook_response.status_code == 200:
                playbook_count = playbook_response.json().get('count', 0)
                print(f"   📖 Generated Playbooks: {playbook_count:,}")
            
        except Exception as e:
            print(f"   ❌ Error fetching metrics: {e}")
    
    async def run_validation(self):
        """Run complete validation suite"""
        print("""
╔═══════════════════════════════════════════════════════════════════╗
║   Enterprise Banking SOC - End-to-End Flow Validation            ║
╚═══════════════════════════════════════════════════════════════════╝
        """)
        
        # 1. Check Service Health
        self.print_header("Service Health Check")
        
        health_checks = {
            'OpenSearch': self.check_opensearch(),
            'Vector': self.check_vector_metrics(),
            'AI Intelligence': self.check_service_health('AI Intelligence', self.services['ai_intelligence']),
            'Enrichment': self.check_service_health('Enrichment', self.services['enrichment']),
            'SOAR': self.check_service_health('SOAR', self.services['soar']),
        }
        
        results = {}
        for name, check in health_checks.items():
            results[name] = await check
        
        # 2. Test Log Ingestion
        ingestion_result = await self.test_log_ingestion()
        
        # 3. Test Incident Flow
        incident_result = await self.test_incident_flow()
        
        # 4. Check Metrics
        await self.check_data_flow_metrics()
        
        # 5. Summary
        self.print_header("Validation Summary")
        
        total_checks = len(results) + 2  # health checks + 2 flow tests
        passed_checks = sum(results.values()) + ingestion_result + incident_result
        
        print(f"   Total Checks: {total_checks}")
        print(f"   Passed: {passed_checks}")
        print(f"   Failed: {total_checks - passed_checks}")
        print(f"   Success Rate: {(passed_checks/total_checks)*100:.1f}%")
        
        if passed_checks == total_checks:
            print("\n   🎉 ALL CHECKS PASSED - Pipeline is fully operational!")
            return 0
        elif passed_checks >= total_checks * 0.7:
            print("\n   ⚠️  PARTIAL SUCCESS - Some components need attention")
            return 1
        else:
            print("\n   ❌ VALIDATION FAILED - Pipeline has critical issues")
            return 2

async def main():
    """Main entry point"""
    validator = FlowValidator()
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    exit_code = await validator.run_validation()
    sys.exit(exit_code)

if __name__ == "__main__":
    asyncio.run(main())
