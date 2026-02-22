import { ServiceStatus } from './types'

// Fixed reference date prevents SSR/CSR hydration mismatches
const SEED_DATE = new Date('2026-02-18T00:00:00Z')

export const SERVICES: ServiceStatus[] = [
  {
    id: 'wazuh',
    name: 'Wazuh',
    icon: 'Shield',
    status: 'healthy',
    uptime: 99.95,
    lastCheck: SEED_DATE,
    dashboardUrl: 'https://wazuh.example.com',
    description: 'Threat Detection & Response'
  },
  {
    id: 'opensearch',
    name: 'OpenSearch',
    icon: 'Database',
    status: 'healthy',
    uptime: 99.98,
    lastCheck: SEED_DATE,
    dashboardUrl: 'https://opensearch.example.com',
    description: 'Log Analytics & Search'
  },
  {
    id: 'ai-intel',
    name: 'AI Intelligence',
    icon: 'Brain',
    status: 'healthy',
    uptime: 99.87,
    lastCheck: SEED_DATE,
    dashboardUrl: 'https://ai.example.com',
    description: 'UEBA + Anomaly Detection Engine'
  },
  {
    id: 'soar',
    name: 'SOAR Platform',
    icon: 'Zap',
    status: 'healthy',
    uptime: 99.92,
    lastCheck: SEED_DATE,
    dashboardUrl: 'https://soar.example.com',
    description: 'Security Automation & Response'
  },
  {
    id: 'enrichment',
    name: 'Enrichment Layer',
    icon: 'Activity',
    status: 'healthy',
    uptime: 99.80,
    lastCheck: SEED_DATE,
    dashboardUrl: 'https://enrichment.example.com',
    description: 'CVE/IOC/LLM Playbook Generation'
  },
  {
    id: 'vector',
    name: 'Vector ETL',
    icon: 'ArrowRightLeft',
    status: 'healthy',
    uptime: 99.97,
    lastCheck: SEED_DATE,
    dashboardUrl: 'http://localhost:8686',
    description: 'Log Normalization & Enrichment'
  },
  {
    id: 'edr',
    name: 'EDR Platform',
    icon: 'Laptop',
    status: 'healthy',
    uptime: 99.94,
    lastCheck: SEED_DATE,
    dashboardUrl: 'https://edr.example.com',
    description: 'Endpoint Detection & Response'
  },
  {
    id: 'ndr',
    name: 'NDR Platform',
    icon: 'Radio',
    status: 'healthy',
    uptime: 99.89,
    lastCheck: SEED_DATE,
    dashboardUrl: 'https://ndr.example.com',
    description: 'Network Detection & Response'
  },
  {
    id: 'vault',
    name: 'Secret Vault',
    icon: 'Key',
    status: 'healthy',
    uptime: 99.99,
    lastCheck: SEED_DATE,
    dashboardUrl: 'https://vault.example.com',
    description: 'Secrets Management'
  }
]

export const INTEGRATIONS = [
  { id: 'slack', name: 'Slack Notifications', enabled: true },
  { id: 'jira', name: 'Jira Integration', enabled: true },
  { id: 'splunk', name: 'Splunk Forwarding', enabled: false },
  { id: 'servicenow', name: 'ServiceNow Sync', enabled: true },
  { id: 'teams', name: 'MS Teams', enabled: false },
  { id: 'pagerduty', name: 'PagerDuty', enabled: true },
  { id: 'aws', name: 'AWS CloudTrail', enabled: true },
  { id: 'azure', name: 'Azure Sentinel', enabled: false },
  { id: 'kafka', name: 'Kafka Streaming', enabled: true },
  { id: 'webhook', name: 'Custom Webhooks', enabled: false }
]

export const ALLOWED_FILE_TYPES = ['.log', '.json', '.csv', '.txt', '.evtx']
export const MAX_FILE_SIZE = 500 * 1024 * 1024 // 500MB

export const PIPELINE_STAGES = [
  { id: 'ingestion', name: 'Ingestion', icon: 'Upload' },
  { id: 'parsing', name: 'Parsing', icon: 'FileText' },
  { id: 'enrichment', name: 'Enrichment', icon: 'Layers' },
  { id: 'detection', name: 'Detection', icon: 'AlertTriangle' },
  { id: 'response', name: 'Response', icon: 'CheckCircle' }
]
