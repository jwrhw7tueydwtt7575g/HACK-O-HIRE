#!/usr/bin/env python3
"""
LLM Playbook Generation Service
Transforms enriched incidents into actionable response playbooks
Supports both on-premises (LLaMA 3, Mistral) and cloud (GPT-4o) LLMs
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

import openai
from anthropic import Anthropic
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

from core.config import Settings
from models.incident import EnrichedIncident, PlaybookResponse, ActionBlock

logger = logging.getLogger(__name__)

class LLMPlaybookService:
    """
    LLM-powered playbook generation service
    Generates tailored response playbooks based on enriched incident context
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.llm_config = settings.llm
        self.prompt_templates = {}
        self.local_model = None
        self.local_tokenizer = None
        self.openai_client = None
        self.anthropic_client = None
        
    async def initialize(self):
        """Initialize LLM service"""
        logger.info("Initializing LLM Playbook Service...")
        
        try:
            # Load prompt templates
            await self._load_prompt_templates()
            
            # Initialize LLM backends based on configuration
            if self.llm_config.get('mode') == 'on_premises':
                await self._initialize_local_model()
            elif self.llm_config.get('mode') == 'cloud':
                await self._initialize_cloud_clients()
            else:  # hybrid mode
                await self._initialize_local_model()
                await self._initialize_cloud_clients()
            
            logger.info("✅ LLM Playbook Service initialized")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize LLM service: {e}")
            raise
    
    async def _load_prompt_templates(self):
        """Load prompt templates from files"""
        prompts_dir = Path(self.settings.prompts_dir)
        
        template_files = {
            'incident_analysis': 'incident_analysis.txt',
            'playbook_generation': 'playbook_generation.txt',
            'executive_summary': 'executive_summary.txt',
            'technical_details': 'technical_details.txt',
            'soar_actions': 'soar_actions.txt'
        }
        
        for template_name, filename in template_files.items():
            template_path = prompts_dir / filename
            if template_path.exists():
                with open(template_path, 'r') as f:
                    self.prompt_templates[template_name] = f.read()
                logger.info(f"Loaded prompt template: {template_name}")
            else:
                logger.warning(f"Prompt template not found: {filename}")
                # Use default template
                self.prompt_templates[template_name] = self._get_default_template(template_name)
    
    def _get_default_template(self, template_name: str) -> str:
        """Get default prompt template"""
        templates = {
            'incident_analysis': """
You are a senior cybersecurity analyst at an enterprise banking institution. Analyze the following security incident and provide comprehensive insights.

**Incident Context:**
{incident_context}

**Enrichment Data:**
- CVE Information: {cve_data}
- Threat Intelligence: {threat_intel}
- MITRE ATT&CK: {mitre_context}
- Asset Criticality: {asset_criticality}
- Risk Score: {risk_score}

**Analysis Requirements:**
1. Threat Assessment: Evaluate the severity and potential impact
2. Attack Chain: Reconstruct the sequence of events
3. Business Impact: Assess impact on banking operations
4. Urgency Level: Determine response priority

Provide your analysis in a structured format.
""",
            'playbook_generation': """
You are an incident response expert for enterprise banking security operations. Generate a detailed response playbook for the following security incident.

**Incident Summary:**
{incident_summary}

**Context:**
- Severity: {severity}
- Affected Assets: {affected_assets}
- Attack Techniques: {attack_techniques}
- Business Impact: {business_impact}

**Generate a response playbook that includes:**
1. **Immediate Actions** (0-15 minutes)
   - Containment steps
   - Evidence preservation
   - Stakeholder notification

2. **Investigation Phase** (15-60 minutes)
   - Data collection steps
   - Analysis procedures
   - Scope determination

3. **Remediation Phase** (1-4 hours)
   - Threat elimination
   - System restoration
   - Security hardening

4. **Recovery Phase** (4-24 hours)
   - Service restoration
   - Monitoring enhancement
   - Lessons learned

**Important:** Consider banking compliance requirements (PCI-DSS, SOX, Basel III) and regulatory reporting obligations.

Provide step-by-step actions with specific commands, tools, and decision points.
""",
            'executive_summary': """
You are the CISO of an enterprise bank. Create an executive summary of the following security incident for board-level briefing.

**Incident Details:**
{incident_details}

**Generate an executive summary that includes:**
1. **Situation Overview** (What happened)
2. **Business Impact** (Financial, operational, reputational)
3. **Response Actions** (What we're doing)
4. **Current Status** (Where we are now)
5. **Next Steps** (What comes next)
6. **Regulatory Considerations** (Reporting requirements)

**Target Audience:** Board of Directors, C-Suite, Regulators
**Tone:** Professional, clear, non-technical
**Length:** Maximum 500 words
""",
            'technical_details': """
You are a senior SOC analyst documenting a security incident for technical teams. Provide detailed technical analysis.

**Incident Data:**
{incident_data}

**Generate technical documentation including:**
1. **Technical Timeline** - Precise sequence of events
2. **Indicators of Compromise (IoCs)** - IPs, hashes, domains
3. **Attack Techniques** - Detailed MITRE ATT&CK mapping
4. **Evidence Artifacts** - Logs, files, network captures
5. **Forensic Findings** - Analysis results
6. **Remediation Details** - Technical steps taken

**Format:** Technical documentation suitable for incident report and knowledge base.
""",
            'soar_actions': """
You are an automation engineer designing SOAR playbook actions. Convert the incident response plan into machine-readable actions.

**Incident Response Plan:**
{response_plan}

**Generate SOAR actions as JSON array with the following structure:**
```json
[
  {{
    "action_id": "unique_id",
    "action_type": "isolate_host|block_ip|reset_password|disable_account|send_notification",
    "priority": 1-10,
    "automated": true|false,
    "approval_required": true|false,
    "parameters": {{}},
    "expected_duration_seconds": 60,
    "rollback_action": "action_id or null",
    "success_criteria": "description"
  }}
]
```

**Requirements:**
- Actions must be idempotent
- Include rollback procedures
- Specify approval requirements based on impact
- Consider banking operational hours and customer impact
"""}
        
        return templates.get(template_name, "")
    
    async def _initialize_local_model(self):
        """Initialize local LLM model (LLaMA 3, Mistral)"""
        logger.info("Initializing local LLM model...")
        
        try:
            model_name = self.llm_config.get('local_model', 'meta-llama/Llama-2-13b-chat-hf')
            
            # Load tokenizer and model
            self.local_tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.local_model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16,
                device_map="auto",
                low_cpu_mem_usage=True
            )
            
            logger.info(f"✅ Loaded local model: {model_name}")
            
        except Exception as e:
            logger.warning(f"⚠️  Could not load local model: {e}")
            logger.info("Falling back to cloud-based LLM")
    
    async def _initialize_cloud_clients(self):
        """Initialize cloud LLM clients (OpenAI, Anthropic)"""
        logger.info("Initializing cloud LLM clients...")
        
        try:
            # OpenAI (GPT-4o)
            openai_api_key = self.llm_config.get('openai_api_key')
            if openai_api_key:
                self.openai_client = openai.OpenAI(api_key=openai_api_key)
                logger.info("✅ OpenAI client initialized")
            
            # Anthropic (Claude)
            anthropic_api_key = self.llm_config.get('anthropic_api_key')
            if anthropic_api_key:
                self.anthropic_client = Anthropic(api_key=anthropic_api_key)
                logger.info("✅ Anthropic client initialized")
                
        except Exception as e:
            logger.error(f"❌ Failed to initialize cloud clients: {e}")
    
    async def generate_playbook(self, enriched_incident: EnrichedIncident) -> PlaybookResponse:
        """
        Generate comprehensive response playbook from enriched incident
        """
        logger.info(f"Generating playbook for incident {enriched_incident.incident_id}")
        
        try:
            # Prepare context from enriched incident
            incident_context = self._prepare_incident_context(enriched_incident)
            
            # Generate different playbook components
            analysis = await self._generate_incident_analysis(incident_context)
            detailed_playbook = await self._generate_detailed_playbook(incident_context, analysis)
            executive_summary = await self._generate_executive_summary(incident_context)
            technical_details = await self._generate_technical_details(incident_context)
            soar_actions = await self._generate_soar_actions(detailed_playbook)
            
            # Construct playbook response
            playbook = PlaybookResponse(
                incident_id=enriched_incident.incident_id,
                generated_at=datetime.now(),
                model_used=self._get_active_model_name(),
                
                # Core playbook content
                incident_analysis=analysis,
                response_playbook=detailed_playbook,
                executive_summary=executive_summary,
                technical_documentation=technical_details,
                
                # Actionable outputs
                soar_actions=soar_actions,
                recommended_priority=self._determine_priority(enriched_incident),
                estimated_resolution_time_hours=self._estimate_resolution_time(enriched_incident),
                
                # Metadata
                compliance_considerations=self._extract_compliance_requirements(enriched_incident),
                stakeholder_notifications=self._identify_stakeholders(enriched_incident),
                
                # Confidence and quality metrics
                confidence_score=self._calculate_playbook_confidence(enriched_incident),
                playbook_version="1.0.0"
            )
            
            logger.info(f"✅ Generated playbook for incident {enriched_incident.incident_id}")
            return playbook
            
        except Exception as e:
            logger.error(f"❌ Failed to generate playbook: {e}")
            raise
    
    def _prepare_incident_context(self, incident: EnrichedIncident) -> Dict:
        """Prepare structured context for LLM prompts"""
        return {
            'incident_id': incident.incident_id,
            'timestamp': incident.timestamp.isoformat(),
            'severity': incident.severity,
            'risk_score': incident.risk_score,
            'confidence': incident.confidence,
            'affected_assets': ', '.join(incident.affected_assets or []),
            'cve_data': json.dumps(incident.cve_matches or [], indent=2),
            'threat_intel': json.dumps(incident.threat_intel_matches or [], indent=2),
            'mitre_context': json.dumps(incident.mitre_attack_context or {}, indent=2),
            'asset_criticality': incident.asset_criticality_score,
            'attack_techniques': ', '.join(incident.attack_techniques or []),
            'business_impact': incident.business_impact,
            'original_alerts': json.dumps(incident.original_alerts or [], indent=2)
        }
    
    async def _generate_incident_analysis(self, context: Dict) -> str:
        """Generate comprehensive incident analysis"""
        prompt = self.prompt_templates['incident_analysis'].format(**context)
        response = await self._call_llm(prompt, max_tokens=1000)
        return response
    
    async def _generate_detailed_playbook(self, context: Dict, analysis: str) -> str:
        """Generate detailed response playbook"""
        context['incident_summary'] = analysis
        prompt = self.prompt_templates['playbook_generation'].format(**context)
        response = await self._call_llm(prompt, max_tokens=2000)
        return response
    
    async def _generate_executive_summary(self, context: Dict) -> str:
        """Generate executive-level summary"""
        context['incident_details'] = json.dumps(context, indent=2)
        prompt = self.prompt_templates['executive_summary'].format(**context)
        response = await self._call_llm(prompt, max_tokens=600)
        return response
    
    async def _generate_technical_details(self, context: Dict) -> str:
        """Generate technical documentation"""
        context['incident_data'] = json.dumps(context, indent=2)
        prompt = self.prompt_templates['technical_details'].format(**context)
        response = await self._call_llm(prompt, max_tokens=1500)
        return response
    
    async def _generate_soar_actions(self, playbook: str) -> List[ActionBlock]:
        """Generate machine-readable SOAR actions"""
        prompt = self.prompt_templates['soar_actions'].format(response_plan=playbook)
        response = await self._call_llm(prompt, max_tokens=1500)
        
        try:
            # Parse JSON response into ActionBlock objects
            actions_data = json.loads(response)
            actions = [ActionBlock(**action) for action in actions_data]
            return actions
        except Exception as e:
            logger.error(f"Failed to parse SOAR actions: {e}")
            return []
    
    async def _call_llm(self, prompt: str, max_tokens: int = 1000) -> str:
        """Call LLM backend (local or cloud)"""
        try:
            # Try cloud first if available (faster response)
            if self.openai_client:
                return await self._call_openai(prompt, max_tokens)
            elif self.anthropic_client:
                return await self._call_anthropic(prompt, max_tokens)
            elif self.local_model:
                return await self._call_local_model(prompt, max_tokens)
            else:
                raise Exception("No LLM backend available")
                
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return "Error generating response. Please retry or use manual analysis."
    
    async def _call_openai(self, prompt: str, max_tokens: int) -> str:
        """Call OpenAI GPT-4o API"""
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are an expert cybersecurity analyst for enterprise banking security operations."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens,
                temperature=0.3,  # Lower temperature for more focused, factual responses
                top_p=0.95
            )
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")
            raise
    
    async def _call_anthropic(self, prompt: str, max_tokens: int) -> str:
        """Call Anthropic Claude API"""
        try:
            message = self.anthropic_client.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=max_tokens,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            return message.content[0].text
            
        except Exception as e:
            logger.error(f"Anthropic API call failed: {e}")
            raise
    
    async def _call_local_model(self, prompt: str, max_tokens: int) -> str:
        """Call local LLM model (LLaMA, Mistral)"""
        try:
            inputs = self.local_tokenizer(prompt, return_tensors="pt").to(self.local_model.device)
            
            with torch.no_grad():
                outputs = self.local_model.generate(
                    **inputs,
                    max_new_tokens=max_tokens,
                    temperature=0.3,
                    top_p=0.95,
                    do_sample=True
                )
            
            response = self.local_tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Extract only the generated response (remove prompt)
            response = response[len(prompt):].strip()
            return response
            
        except Exception as e:
            logger.error(f"Local model inference failed: {e}")
            raise
    
    def _get_active_model_name(self) -> str:
        """Get name of currently active LLM model"""
        if self.openai_client:
            return "gpt-4o"
        elif self.anthropic_client:
            return "claude-3-opus"
        elif self.local_model:
            return self.llm_config.get('local_model', 'local-llm')
        return "unknown"
    
    def _determine_priority(self, incident: EnrichedIncident) -> str:
        """Determine incident priority level"""
        if incident.risk_score >= 0.9:
            return "CRITICAL"
        elif incident.risk_score >= 0.8:
            return "HIGH"
        elif incident.risk_score >= 0.6:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _estimate_resolution_time(self, incident: EnrichedIncident) -> int:
        """Estimate time to resolve incident (hours)"""
        base_time = {
            "CRITICAL": 4,
            "HIGH": 8,
            "MEDIUM": 24,
            "LOW": 48
        }
        
        priority = self._determine_priority(incident)
        hours = base_time.get(priority, 24)
        
        # Adjust based on complexity
        if incident.cve_matches and len(incident.cve_matches) > 3:
            hours *= 1.5
        
        if incident.asset_criticality_score and incident.asset_criticality_score > 8:
            hours *= 1.2
        
        return int(hours)
    
    def _extract_compliance_requirements(self, incident: EnrichedIncident) -> List[str]:
        """Extract applicable compliance requirements"""
        requirements = []
        
        # Check for PCI-DSS
        if any('payment' in str(asset).lower() or 'card' in str(asset).lower() 
               for asset in (incident.affected_assets or [])):
            requirements.append("PCI-DSS: Incident must be reported within 72 hours")
        
        # Check for SOX
        if any('financial' in str(asset).lower() or 'accounting' in str(asset).lower() 
               for asset in (incident.affected_assets or [])):
            requirements.append("SOX: Document all changes to financial systems")
        
        # Check for data breach notification
        if incident.risk_score >= 0.8:
            requirements.append("Data Breach Notification: Assess if customer data was compromised")
        
        # Basel III operational risk
        if incident.asset_criticality_score and incident.asset_criticality_score >= 8:
            requirements.append("Basel III: Report as operational risk event")
        
        return requirements
    
    def _identify_stakeholders(self, incident: EnrichedIncident) -> List[Dict]:
        """Identify stakeholders to be notified"""
        stakeholders = []
        
        priority = self._determine_priority(incident)
        
        # Always notify SOC team
        stakeholders.append({
            "role": "SOC Team",
            "notification_method": "Slack + Email",
            "urgency": "immediate"
        })
        
        if priority in ["HIGH", "CRITICAL"]:
            stakeholders.append({
                "role": "CISO",
                "notification_method": "Phone + Email",
                "urgency": "immediate"
            })
        
        if priority == "CRITICAL":
            stakeholders.extend([
                {
                    "role": "CTO",
                    "notification_method": "Phone + Email",
                    "urgency": "immediate"
                },
                {
                    "role": "CEO",
                    "notification_method": "Email + Briefing",
                    "urgency": "within 1 hour"
                },
                {
                    "role": "Board of Directors",
                    "notification_method": "Formal Report",
                    "urgency": "within 24 hours"
                }
            ])
        
        # Regulatory notifications for severe incidents
        if incident.risk_score >= 0.85:
            stakeholders.append({
                "role": "Regulatory Affairs",
                "notification_method": "Formal Report",
                "urgency": "as per regulatory requirements"
            })
        
        return stakeholders
    
    def _calculate_playbook_confidence(self, incident: EnrichedIncident) -> float:
        """Calculate confidence score for generated playbook"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence with more enrichment data
        if incident.cve_matches:
            confidence += 0.1
        
        if incident.threat_intel_matches:
            confidence += 0.1
        
        if incident.mitre_attack_context:
            confidence += 0.1
        
        if incident.asset_criticality_score:
            confidence += 0.1
        
        # Adjust based on incident confidence
        if incident.confidence:
            confidence = (confidence + incident.confidence) / 2
        
        return min(1.0, confidence)
    
    async def shutdown(self):
        """Shutdown LLM service"""
        logger.info("Shutting down LLM Playbook Service...")
        
        # Cleanup model resources
        if self.local_model:
            del self.local_model
            del self.local_tokenizer
            torch.cuda.empty_cache()
        
        logger.info("✅ LLM Playbook Service shutdown complete")