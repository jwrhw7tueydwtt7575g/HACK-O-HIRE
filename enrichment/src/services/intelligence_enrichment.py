#!/usr/bin/env python3
"""
Intelligence Enrichment Service
CVE/NVD lookup, CISA KEV, threat intel IOC matching, asset criticality
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path
import aiohttp
from urllib.parse import quote

from core.config import Settings
from core.database import OpenSearchClient, RedisClient
from models.incident import EnrichedIncident, CVEMatch, ThreatIntelMatch, AssetInfo

logger = logging.getLogger(__name__)


class IntelligenceEnrichmentService:
    """
    Enriches incidents with external threat intelligence
    - CVE/NVD vulnerability database lookups
    - CISA Known Exploited Vulnerabilities (KEV)
    - Threat intel IOC matching
    - Asset criticality weighting
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.opensearch_client = None
        self.redis_client = None
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Caches
        self.cve_cache = {}
        self.kev_list = set()
        self.threat_intel_iocs = {}
        self.asset_db = {}
        
    async def initialize(self):
        """Initialize enrichment service"""
        logger.info("Initializing Intelligence Enrichment Service...")
        
        try:
            # Initialize HTTP session
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers={'User-Agent': 'Enterprise-Banking-SOC/1.0'}
            )
            
            # Load CISA KEV list
            await self._load_cisa_kev()
            
            # Load threat intel feeds
            await self._load_threat_intel_feeds()
            
            # Load asset database
            await self._load_asset_database()
            
            # Start background refresh tasks
            asyncio.create_task(self._periodic_intel_refresh())
            
            logger.info("✅ Intelligence Enrichment Service initialized")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize enrichment service: {e}")
            raise
    
    async def enrich_incident(self, incident: EnrichedIncident) -> EnrichedIncident:
        """
        Enrich incident with comprehensive threat intelligence
        """
        logger.info(f"Enriching incident {incident.incident_id}")
        
        try:
            # Parallel enrichment tasks
            cve_task = self._enrich_cve(incident)
            threat_intel_task = self._enrich_threat_intel(incident)
            asset_task = self._enrich_asset_criticality(incident)
            mitre_task = self._enrich_mitre_context(incident)
            
            # Wait for all enrichments
            cve_matches, threat_matches, asset_info, mitre_context = await asyncio.gather(
                cve_task,
                threat_intel_task,
                asset_task,
                mitre_task,
                return_exceptions=True
            )
            
            # Apply enrichments (handle exceptions)
            if not isinstance(cve_matches, Exception):
                incident.cve_matches = cve_matches
            
            if not isinstance(threat_matches, Exception):
                incident.threat_intel_matches = threat_matches
            
            if not isinstance(asset_info, Exception):
                incident.asset_information = asset_info['assets']
                incident.asset_criticality_score = asset_info['max_criticality']
            
            if not isinstance(mitre_context, Exception):
                incident.mitre_attack_context = mitre_context
            
            # Calculate business impact
            incident.business_impact = self._calculate_business_impact(incident)
            
            # Update enrichment metadata
            incident.enriched_at = datetime.now()
            incident.enrichment_sources = [
                'nvd', 'cisa_kev', 'threat_intel', 'asset_db', 'mitre'
            ]
            
            # Recalculate risk score with enriched data
            incident.risk_score = self._calculate_enriched_risk_score(incident)
            
            logger.info(f"✅ Enriched incident {incident.incident_id} - Risk: {incident.risk_score:.2f}")
            
            return incident
            
        except Exception as e:
            logger.error(f"❌ Failed to enrich incident: {e}")
            raise
    
    async def _enrich_cve(self, incident: EnrichedIncident) -> List[CVEMatch]:
        """Enrich with CVE/NVD data"""
        cve_matches = []
        
        try:
            # Extract CVE IDs from logs and alerts
            cve_ids = self._extract_cve_ids(incident)
            
            for cve_id in cve_ids:
                # Check cache first
                if cve_id in self.cve_cache:
                    cve_data = self.cve_cache[cve_id]
                else:
                    # Fetch from NVD API
                    cve_data = await self._fetch_nvd_cve(cve_id)
                    if cve_data:
                        self.cve_cache[cve_id] = cve_data
                
                if cve_data:
                    cve_match = CVEMatch(
                        cve_id=cve_id,
                        description=cve_data.get('description', ''),
                        cvss_score=cve_data.get('cvss_score'),
                        cvss_vector=cve_data.get('cvss_vector'),
                        exploit_available=self._check_exploit_availability(cve_id),
                        in_cisa_kev=cve_id in self.kev_list,
                        published_date=cve_data.get('published_date'),
                        last_modified=cve_data.get('last_modified'),
                        references=cve_data.get('references', []),
                        cwe=cve_data.get('cwe'),
                        affected_products=cve_data.get('affected_products', [])
                    )
                    cve_matches.append(cve_match)
            
            return cve_matches
            
        except Exception as e:
            logger.error(f"CVE enrichment failed: {e}")
            return []
    
    async def _fetch_nvd_cve(self, cve_id: str) -> Optional[Dict]:
        """Fetch CVE details from NVD API"""
        try:
            url = f"{self.settings.cve.nvd_base_url}?cveId={cve_id}"
            headers = {}
            
            if self.settings.cve.nvd_api_key:
                headers['apiKey'] = self.settings.cve.nvd_api_key
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('vulnerabilities'):
                        vuln = data['vulnerabilities'][0]['cve']
                        
                        # Extract CVSS score
                        cvss_score = None
                        cvss_vector = None
                        
                        if 'metrics' in vuln:
                            if 'cvssMetricV31' in vuln['metrics']:
                                cvss_data = vuln['metrics']['cvssMetricV31'][0]['cvssData']
                                cvss_score = cvss_data.get('baseScore')
                                cvss_vector = cvss_data.get('vectorString')
                            elif 'cvssMetricV2' in vuln['metrics']:
                                cvss_data = vuln['metrics']['cvssMetricV2'][0]['cvssData']
                                cvss_score = cvss_data.get('baseScore')
                                cvss_vector = cvss_data.get('vectorString')
                        
                        # Extract description
                        description = ""
                        if 'descriptions' in vuln:
                            for desc in vuln['descriptions']:
                                if desc['lang'] == 'en':
                                    description = desc['value']
                                    break
                        
                        # Extract references
                        references = []
                        if 'references' in vuln:
                            references = [ref['url'] for ref in vuln['references'][:10]]
                        
                        # Extract CWE
                        cwe = None
                        if 'weaknesses' in vuln:
                            for weakness in vuln['weaknesses']:
                                if weakness['description']:
                                    cwe = weakness['description'][0]['value']
                                    break
                        
                        return {
                            'description': description,
                            'cvss_score': cvss_score,
                            'cvss_vector': cvss_vector,
                            'published_date': vuln.get('published'),
                            'last_modified': vuln.get('lastModified'),
                            'references': references,
                            'cwe': cwe,
                            'affected_products': []  # Would need detailed parsing
                        }
                
                elif response.status == 429:
                    logger.warning("NVD API rate limit reached")
                    await asyncio.sleep(6)  # Wait before retry
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to fetch CVE {cve_id}: {e}")
            return None
    
    def _extract_cve_ids(self, incident: EnrichedIncident) -> List[str]:
        """Extract CVE IDs from incident data"""
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cve_ids = set()
        
        # Search in description
        cve_ids.update(re.findall(cve_pattern, incident.description, re.IGNORECASE))
        
        # Search in title
        cve_ids.update(re.findall(cve_pattern, incident.title, re.IGNORECASE))
        
        # Search in raw logs
        for log in incident.raw_logs:
            cve_ids.update(re.findall(cve_pattern, log, re.IGNORECASE))
        
        return list(cve_ids)
    
    def _check_exploit_availability(self, cve_id: str) -> bool:
        """Check if exploit is publicly available"""
        # Simplified check - in production would query Exploit-DB, Metasploit, etc.
        # For now, check if CVSS score is high and in CISA KEV
        return cve_id in self.kev_list
    
    async def _load_cisa_kev(self):
        """Load CISA Known Exploited Vulnerabilities list"""
        try:
            logger.info("Loading CISA KEV list...")
            
            async with self.session.get(self.settings.cve.cisa_kev_url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for vuln in data.get('vulnerabilities', []):
                        self.kev_list.add(vuln['cveID'])
                    
                    logger.info(f"✅ Loaded {len(self.kev_list)} CISA KEV entries")
                else:
                    logger.warning(f"Failed to load CISA KEV: {response.status}")
                    
        except Exception as e:
            logger.error(f"Failed to load CISA KEV: {e}")
    
    async def _enrich_threat_intel(self, incident: EnrichedIncident) -> List[ThreatIntelMatch]:
        """Enrich with threat intelligence IOC matches"""
        threat_matches = []
        
        try:
            # Extract IOCs from incident
            iocs = self._extract_iocs(incident)
            
            for ioc_type, ioc_values in iocs.items():
                for ioc_value in ioc_values:
                    # Check against threat intel feeds
                    if ioc_value in self.threat_intel_iocs.get(ioc_type, {}):
                        intel_data = self.threat_intel_iocs[ioc_type][ioc_value]
                        
                        match = ThreatIntelMatch(
                            ioc_value=ioc_value,
                            ioc_type=ioc_type,
                            source_feed=intel_data['source'],
                            confidence=intel_data.get('confidence', 0.7),
                            first_seen=intel_data.get('first_seen', datetime.now()),
                            last_seen=intel_data.get('last_seen', datetime.now()),
                            tags=intel_data.get('tags', []),
                            threat_actor=intel_data.get('threat_actor'),
                            campaign=intel_data.get('campaign'),
                            malware_family=intel_data.get('malware_family')
                        )
                        threat_matches.append(match)
            
            return threat_matches
            
        except Exception as e:
            logger.error(f"Threat intel enrichment failed: {e}")
            return []
    
    def _extract_iocs(self, incident: EnrichedIncident) -> Dict[str, List[str]]:
        """Extract IOCs (IPs, domains, hashes, URLs) from incident"""
        import re
        
        iocs = {
            'ip': set(),
            'domain': set(),
            'hash': set(),
            'url': set()
        }
        
        # Combine all text sources
        text = f"{incident.title} {incident.description} "
        text += " ".join(incident.raw_logs)
        text += json.dumps(incident.original_alerts)
        
        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        iocs['ip'].update(re.findall(ip_pattern, text))
        
        # Domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        iocs['domain'].update(re.findall(domain_pattern, text))
        
        # MD5/SHA256 hashes
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        iocs['hash'].update(re.findall(hash_pattern, text))
        
        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        iocs['url'].update(re.findall(url_pattern, text))
        
        return {k: list(v) for k, v in iocs.items()}
    
    async def _load_threat_intel_feeds(self):
        """Load threat intelligence feeds"""
        logger.info("Loading threat intelligence feeds...")
        
        feed_loaders = {
            'abuse_ch': self._load_abuse_ch_feed,
            'emergingthreats': self._load_emergingthreats_feed
        }
        
        for feed_name, loader in feed_loaders.items():
            try:
                await loader()
            except Exception as e:
                logger.warning(f"Failed to load {feed_name} feed: {e}")
        
        logger.info(f"✅ Loaded {sum(len(v) for v in self.threat_intel_iocs.values())} threat IOCs")
    
    async def _load_abuse_ch_feed(self):
        """Load Abuse.ch SSL Blacklist"""
        try:
            url = self.settings.threat_intel.feeds.get('abuse_ch')
            if not url:
                return
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    
                    if 'ip' not in self.threat_intel_iocs:
                        self.threat_intel_iocs['ip'] = {}
                    
                    for line in text.split('\n'):
                        if line and not line.startswith('#'):
                            ip = line.strip()
                            self.threat_intel_iocs['ip'][ip] = {
                                'source': 'abuse.ch',
                                'confidence': 0.9,
                                'first_seen': datetime.now(),
                                'last_seen': datetime.now(),
                                'tags': ['malware', 'c2']
                            }
                            
        except Exception as e:
            logger.error(f"Failed to load Abuse.ch feed: {e}")
    
    async def _load_emergingthreats_feed(self):
        """Load EmergingThreats IP blocklist"""
        try:
            url = self.settings.threat_intel.feeds.get('emergingthreats')
            if not url:
                return
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    
                    if 'ip' not in self.threat_intel_iocs:
                        self.threat_intel_iocs['ip'] = {}
                    
                    for line in text.split('\n'):
                        if line and not line.startswith('#'):
                            ip = line.strip()
                            self.threat_intel_iocs['ip'][ip] = {
                                'source': 'emergingthreats',
                                'confidence': 0.85,
                                'first_seen': datetime.now(),
                                'last_seen': datetime.now(),
                                'tags': ['suspicious', 'emerging_threat']
                            }
                            
        except Exception as e:
            logger.error(f"Failed to load EmergingThreats feed: {e}")
    
    async def _enrich_asset_criticality(self, incident: EnrichedIncident) -> Dict:
        """Enrich with asset criticality information"""
        assets = []
        max_criticality = 0
        
        try:
            for asset_id in incident.affected_assets:
                asset_info = self.asset_db.get(asset_id)
                
                if asset_info:
                    asset = AssetInfo(**asset_info)
                    assets.append(asset)
                    max_criticality = max(max_criticality, asset.criticality_score)
                else:
                    # Default asset if not in database
                    asset = AssetInfo(
                        asset_id=asset_id,
                        asset_name=asset_id,
                        asset_type='unknown',
                        business_unit='unknown',
                        criticality_score=self.settings.asset.default_criticality
                    )
                    assets.append(asset)
                    max_criticality = max(max_criticality, asset.criticality_score)
            
            return {
                'assets': assets,
                'max_criticality': max_criticality
            }
            
        except Exception as e:
            logger.error(f"Asset enrichment failed: {e}")
            return {'assets': [], 'max_criticality': 0}
    
    async def _load_asset_database(self):
        """Load asset database"""
        try:
            asset_db_path = Path(self.settings.asset.asset_db_path)
            
            if asset_db_path.exists():
                with open(asset_db_path, 'r') as f:
                    self.asset_db = json.load(f)
                logger.info(f"✅ Loaded {len(self.asset_db)} assets from database")
            else:
                logger.warning(f"Asset database not found: {asset_db_path}")
                # Create sample asset database
                self._create_sample_asset_db()
                
        except Exception as e:
            logger.error(f"Failed to load asset database: {e}")
    
    def _create_sample_asset_db(self):
        """Create sample asset database"""
        self.asset_db = {
            'core-banking-01': {
                'asset_id': 'core-banking-01',
                'asset_name': 'Core Banking Primary Server',
                'asset_type': 'server',
                'business_unit': 'core_banking',
                'criticality_score': 10,
                'owner': 'ops@bank.com',
                'location': 'DC1',
                'ip_addresses': ['10.0.1.10'],
                'hostnames': ['core-banking-01.internal']
            },
            'api-gateway-01': {
                'asset_id': 'api-gateway-01',
                'asset_name': 'API Gateway',
                'asset_type': 'server',
                'business_unit': 'payments',
                'criticality_score': 9,
                'owner': 'api-team@bank.com',
                'location': 'DC1',
                'ip_addresses': ['10.0.2.10'],
                'hostnames': ['api.bank.com']
            }
        }
        logger.info("Created sample asset database")
    
    async def _enrich_mitre_context(self, incident: EnrichedIncident) -> Dict:
        """Enrich with MITRE ATT&CK context"""
        try:
            mitre_context = {
                'techniques': [],
                'tactics': set(),
                'attack_chain': []
            }
            
            # Map attack techniques to MITRE
            technique_mapping = {
                'T1078': {'name': 'Valid Accounts', 'tactic': 'Initial Access'},
                'T1110': {'name': 'Brute Force', 'tactic': 'Credential Access'},
                'T1136': {'name': 'Create Account', 'tactic': 'Persistence'},
                'T1071': {'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},
                'T1486': {'name': 'Data Encrypted for Impact', 'tactic': 'Impact'},
                'T1567': {'name': 'Exfiltration Over Web Service', 'tactic': 'Exfiltration'}
            }
            
            for technique_id in incident.attack_techniques:
                if technique_id in technique_mapping:
                    technique_data = technique_mapping[technique_id]
                    mitre_context['techniques'].append({
                        'id': technique_id,
                        'name': technique_data['name'],
                        'tactic': technique_data['tactic']
                    })
                    mitre_context['tactics'].add(technique_data['tactic'])
            
            mitre_context['tactics'] = list(mitre_context['tactics'])
            
            return mitre_context
            
        except Exception as e:
            logger.error(f"MITRE enrichment failed: {e}")
            return {}
    
    def _calculate_business_impact(self, incident: EnrichedIncident) -> str:
        """Calculate business impact description"""
        if incident.asset_criticality_score:
            if incident.asset_criticality_score >= 9:
                return "CRITICAL - Core banking operations at risk"
            elif incident.asset_criticality_score >= 7:
                return "HIGH - Significant business unit impact"
            elif incident.asset_criticality_score >= 5:
                return "MEDIUM - Limited operational impact"
            else:
                return "LOW - Minimal business impact"
        
        return "UNKNOWN - Impact assessment pending"
    
    def _calculate_enriched_risk_score(self, incident: EnrichedIncident) -> float:
        """Recalculate risk score with enriched data"""
        base_score = incident.risk_score
        
        # Factor in CVE severity
        if incident.cve_matches:
            max_cvss = max((cve.cvss_score or 0) for cve in incident.cve_matches)
            cve_factor = max_cvss / 10.0 * 0.3  # 30% weight
        else:
            cve_factor = 0
        
        # Factor in CISA KEV presence
        kev_factor = 0.2 if any(cve.in_cisa_kev for cve in incident.cve_matches) else 0
        
        # Factor in threat intel matches
        threat_factor = min(len(incident.threat_intel_matches) * 0.1, 0.2)
        
        # Factor in asset criticality
        if incident.asset_criticality_score:
            asset_factor = incident.asset_criticality_score / 10.0 * 0.3  # 30% weight
        else:
            asset_factor = 0
        
        # Combine factors
        enriched_score = min(100.0, base_score + (cve_factor + kev_factor + threat_factor + asset_factor) * 100)
        
        return round(enriched_score, 2)
    
    async def _periodic_intel_refresh(self):
        """Periodically refresh threat intelligence"""
        while True:
            try:
                await asyncio.sleep(self.settings.threat_intel.update_interval_hours * 3600)
                
                logger.info("Refreshing threat intelligence feeds...")
                await self._load_cisa_kev()
                await self._load_threat_intel_feeds()
                
            except Exception as e:
                logger.error(f"Periodic intel refresh failed: {e}")
    
    async def shutdown(self):
        """Shutdown enrichment service"""
        logger.info("Shutting down Intelligence Enrichment Service...")
        
        if self.session:
            await self.session.close()
        
        logger.info("✅ Intelligence Enrichment Service shutdown complete")
