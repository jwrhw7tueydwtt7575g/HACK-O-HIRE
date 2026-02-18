import { ServiceStatus } from './types'

export const SERVICES: ServiceStatus[] = [
  {
    id: 'wazuh',
    name: 'Wazuh',
    icon: 'Shield',
    status: 'healthy',
    uptime: 99.95,
    lastCheck: new Date(),
    dashboardUrl: 'https://wazuh.example.com',
    description: 'Threat Detection & Response'
  },
  {
    id: 'opensearch',
    name: 'OpenSearch',
    icon: 'Database',
    status: 'healthy',
    uptime: 99.98,
    lastCheck: new Date(),
    dashboardUrl: 'https://opensearch.example.com',
    description: 'Log Analytics & Search'
  },
  {
    id: 'ai-intel',
    name: 'AI Intelligence',
    icon: 'Brain',
    status: 'healthy',
    uptime: 99.87,
    lastCheck: new Date(),
    dashboardUrl: 'https://ai.example.com',
    description: 'Threat Intelligence Engine'
  },
  {
    id: 'soar',
    name: 'SOAR Platform',
    icon: 'Zap',
    status: 'healthy',
    uptime: 99.92,
    lastCheck: new Date(),
    dashboardUrl: 'https://soar.example.com',
    description: 'Security Automation & Response'
  },
  {
    id: 'siem',
    name: 'SIEM System',
    icon: 'Activity',
    status: 'degraded',
    uptime: 98.5,
    lastCheck: new Date(),
    dashboardUrl: 'https://siem.example.com',
    description: 'Security Information & Event Management'
  },
  {
    id: 'dlp',
    name: 'DLP Engine',
    icon: 'Lock',
    status: 'healthy',
    uptime: 99.91,
    lastCheck: new Date(),
    dashboardUrl: 'https://dlp.example.com',
    description: 'Data Loss Prevention'
  },
  {
    id: 'edr',
    name: 'EDR Platform',
    icon: 'Laptop',
    status: 'healthy',
    uptime: 99.94,
    lastCheck: new Date(),
    dashboardUrl: 'https://edr.example.com',
    description: 'Endpoint Detection & Response'
  },
  {
    id: 'ndr',
    name: 'NDR Platform',
    icon: 'Radio',
    status: 'healthy',
    uptime: 99.89,
    lastCheck: new Date(),
    dashboardUrl: 'https://ndr.example.com',
    description: 'Network Detection & Response'
  },
  {
    id: 'vault',
    name: 'Secret Vault',
    icon: 'Key',
    status: 'healthy',
    uptime: 99.99,
    lastCheck: new Date(),
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
