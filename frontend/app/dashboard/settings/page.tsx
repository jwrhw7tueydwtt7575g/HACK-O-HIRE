'use client'

import { useState, useEffect } from 'react'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs'
import {
  Brain, Shield, Database, Zap, Server,
  Key, Bell, Eye, EyeOff, Save, RefreshCw,
  CheckCircle, AlertCircle, Network, Bot
} from 'lucide-react'

// ─── Types ───────────────────────────────────────────────────────────────────

interface ConfigSection {
  label: string
  fields: ConfigField[]
}

interface ConfigField {
  key: string
  label: string
  type: 'text' | 'password' | 'select' | 'toggle' | 'number'
  placeholder?: string
  options?: { value: string; label: string }[]
  description?: string
}

// ─── Default config stored in localStorage ───────────────────────────────────

const DEFAULT_CONFIG: Record<string, string | boolean | number> = {
  // Service URLs
  ai_url:               'http://localhost:8001',
  enrichment_url:       'http://localhost:8002',
  soar_url:             'http://localhost:8003',
  opensearch_url:       'http://localhost:9200',
  wazuh_url:            'https://localhost:55000',
  vector_url:           'http://localhost:8686',
  neo4j_url:            'bolt://localhost:7687',
  // LLM
  llm_mode:             'cloud',
  openai_api_key:       '',
  anthropic_api_key:    '',
  local_llm_model:      'meta-llama/Llama-2-13b-chat-hf',
  llm_max_tokens:       2000,
  llm_temperature:      0.3,
  // Threat Intel
  nvd_api_key:          '',
  misp_url:             '',
  misp_api_key:         '',
  alienvault_api_key:   '',
  virustotal_api_key:   '',
  // Notifications
  slack_webhook_url:    '',
  slack_channel:        '#soc-alerts',
  smtp_host:            'smtp.gmail.com',
  smtp_port:            587,
  smtp_user:            '',
  smtp_password:        '',
  pagerduty_api_key:    '',
  teams_webhook_url:    '',
  // Automation
  soar_auto_low:        true,
  soar_auto_medium:     false,
  soar_auto_high:       true,
  soar_auto_critical:   true,
  approval_timeout:     3600,
  // General
  log_level:            'INFO',
  environment:          'production',
  timezone:             'UTC',
}

// ─── Field definitions per tab ────────────────────────────────────────────────

const SECTIONS: Record<string, ConfigSection> = {
  services: {
    label: 'Service URLs',
    fields: [
      { key: 'ai_url',         label: 'AI Intelligence (UEBA)', type: 'text', placeholder: 'http://localhost:8001', description: 'Anomaly detection, UEBA, risk scoring' },
      { key: 'enrichment_url', label: 'Enrichment + LLM',       type: 'text', placeholder: 'http://localhost:8002', description: 'CVE/IOC enrichment, playbook generation' },
      { key: 'soar_url',       label: 'SOAR Automation',        type: 'text', placeholder: 'http://localhost:8003', description: 'Automated response orchestration' },
      { key: 'opensearch_url', label: 'OpenSearch',             type: 'text', placeholder: 'http://localhost:9200', description: 'Log storage and analytics' },
      { key: 'wazuh_url',      label: 'Wazuh API',              type: 'text', placeholder: 'https://localhost:55000', description: 'MITRE tagging and SIEM rules' },
      { key: 'vector_url',     label: 'Vector ETL API',         type: 'text', placeholder: 'http://localhost:8686', description: 'ETL pipeline health and metrics' },
      { key: 'neo4j_url',      label: 'Neo4j Graph DB',         type: 'text', placeholder: 'bolt://localhost:7687',  description: 'Attack chain reconstruction' },
    ]
  },
  llm: {
    label: 'LLM / AI Models',
    fields: [
      { key: 'llm_mode',          label: 'LLM Mode',          type: 'select',   options: [{ value: 'cloud', label: 'Cloud (OpenAI / Claude)' }, { value: 'on_premises', label: 'On-Premises (LLaMA)' }, { value: 'hybrid', label: 'Hybrid (both)' }], description: 'Where playbooks are generated' },
      { key: 'openai_api_key',    label: 'OpenAI API Key',    type: 'password', placeholder: 'sk-...', description: 'GPT-4o for playbook generation' },
      { key: 'anthropic_api_key', label: 'Anthropic API Key', type: 'password', placeholder: 'sk-ant-...', description: 'Claude for playbook generation' },
      { key: 'local_llm_model',   label: 'Local LLM Model',   type: 'text',     placeholder: 'meta-llama/Llama-2-13b-chat-hf', description: 'HuggingFace model ID for on-premises mode' },
      { key: 'llm_max_tokens',    label: 'Max Tokens',        type: 'number',   placeholder: '2000', description: 'Maximum tokens per LLM response' },
      { key: 'llm_temperature',   label: 'Temperature',       type: 'number',   placeholder: '0.3',  description: 'LLM generation temperature (0.0–1.0)' },
    ]
  },
  threat_intel: {
    label: 'Threat Intel Feeds',
    fields: [
      { key: 'nvd_api_key',        label: 'NVD / NIST API Key',    type: 'password', placeholder: 'nvd-api-key', description: 'CVE lookup from nvd.nist.gov' },
      { key: 'misp_url',           label: 'MISP Instance URL',     type: 'text',     placeholder: 'https://misp.yourorg.com', description: 'MISP threat sharing platform' },
      { key: 'misp_api_key',       label: 'MISP API Key',          type: 'password', placeholder: 'misp-auth-key', description: 'MISP authentication key' },
      { key: 'alienvault_api_key', label: 'AlienVault OTX Key',    type: 'password', placeholder: 'otx-api-key', description: 'AlienVault Open Threat Exchange' },
      { key: 'virustotal_api_key', label: 'VirusTotal API Key',    type: 'password', placeholder: 'vt-api-key', description: 'Hash/URL/IP reputation lookups' },
    ]
  },
  notifications: {
    label: 'Notifications',
    fields: [
      { key: 'slack_webhook_url', label: 'Slack Webhook URL',   type: 'password', placeholder: 'https://hooks.slack.com/services/...', description: 'Slack incoming webhook for SOC alerts' },
      { key: 'slack_channel',     label: 'Slack Channel',       type: 'text',     placeholder: '#soc-alerts', description: 'Default Slack channel' },
      { key: 'smtp_host',         label: 'SMTP Host',           type: 'text',     placeholder: 'smtp.gmail.com', description: 'Email server for alert notifications' },
      { key: 'smtp_port',         label: 'SMTP Port',           type: 'number',   placeholder: '587', description: 'SMTP port (587 = TLS, 465 = SSL)' },
      { key: 'smtp_user',         label: 'SMTP Username',       type: 'text',     placeholder: 'alerts@yourbank.com', description: 'Email address for sending alerts' },
      { key: 'smtp_password',     label: 'SMTP Password',       type: 'password', placeholder: 'smtp-password', description: 'Email account password' },
      { key: 'pagerduty_api_key', label: 'PagerDuty API Key',   type: 'password', placeholder: 'pd-api-key', description: 'PagerDuty integration key for critical alerts' },
      { key: 'teams_webhook_url', label: 'MS Teams Webhook',    type: 'password', placeholder: 'https://outlook.office.com/webhook/...', description: 'Microsoft Teams notification webhook' },
    ]
  },
  automation: {
    label: 'SOAR Automation',
    fields: [
      { key: 'soar_auto_low',      label: 'Auto-respond to LOW priority',      type: 'toggle', description: 'Automatically tag, log, create tickets' },
      { key: 'soar_auto_medium',   label: 'Auto-respond to MEDIUM priority',   type: 'toggle', description: 'Requires analyst approval before execution' },
      { key: 'soar_auto_high',     label: 'Auto-respond to HIGH priority',     type: 'toggle', description: 'Auto-execute + notify analyst after' },
      { key: 'soar_auto_critical', label: 'Auto-respond to CRITICAL priority', type: 'toggle', description: 'Auto-execute + activate crisis team bridge' },
      { key: 'approval_timeout',   label: 'Approval Timeout (seconds)',        type: 'number', placeholder: '3600', description: 'How long to wait for analyst approval before expiry' },
    ]
  },
  general: {
    label: 'General',
    fields: [
      { key: 'log_level',    label: 'Log Level',    type: 'select', options: [{ value: 'DEBUG', label: 'DEBUG' }, { value: 'INFO', label: 'INFO' }, { value: 'WARNING', label: 'WARNING' }, { value: 'ERROR', label: 'ERROR' }], description: 'Service log verbosity' },
      { key: 'environment',  label: 'Environment',  type: 'select', options: [{ value: 'production', label: 'Production' }, { value: 'staging', label: 'Staging' }, { value: 'development', label: 'Development' }], description: 'Deployment environment' },
      { key: 'timezone',     label: 'Timezone',     type: 'text',   placeholder: 'UTC', description: 'Timezone for log timestamps and reports' },
    ]
  },
}

const TAB_ICONS: Record<string, React.ElementType> = {
  services:      Network,
  llm:           Bot,
  threat_intel:  Shield,
  notifications: Bell,
  automation:    Zap,
  general:       Server,
}

// ─── PasswordField ────────────────────────────────────────────────────────────

function PasswordField({ value, onChange, placeholder }: {
  value: string; onChange: (v: string) => void; placeholder?: string
}) {
  const [show, setShow] = useState(false)
  return (
    <div className="relative">
      <Input
        type={show ? 'text' : 'password'}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="pr-10 font-mono text-xs"
      />
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 p-0"
        onClick={() => setShow(s => !s)}
      >
        {show ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
      </Button>
    </div>
  )
}

// ─── ServicePingBadge ─────────────────────────────────────────────────────────

function ServicePingBadge({ url }: { url: string }) {
  const [status, setStatus] = useState<'idle' | 'checking' | 'ok' | 'fail'>('idle')

  const check = async () => {
    setStatus('checking')
    try {
      const controller = new AbortController()
      setTimeout(() => controller.abort(), 3000)
      const res = await fetch(`${url}/api/v1/health`, { signal: controller.signal })
      setStatus(res.ok ? 'ok' : 'fail')
    } catch {
      setStatus('fail')
    }
  }

  return (
    <button
      onClick={check}
      className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
      title="Click to test connectivity"
    >
      {status === 'idle'     && <span className="w-2 h-2 rounded-full bg-muted-foreground/40 inline-block" />}
      {status === 'checking' && <RefreshCw className="w-3 h-3 animate-spin text-yellow-500" />}
      {status === 'ok'       && <CheckCircle className="w-3 h-3 text-green-500" />}
      {status === 'fail'     && <AlertCircle className="w-3 h-3 text-red-500" />}
      {status === 'idle'     ? 'Test' : status === 'checking' ? 'Pinging…' : status === 'ok' ? 'Online' : 'Offline'}
    </button>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function SettingsPage() {
  const [config, setConfig] = useState<Record<string, string | boolean | number>>(DEFAULT_CONFIG)
  const [saved, setSaved] = useState(false)

  // Load from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem('soc_config')
      if (stored) setConfig({ ...DEFAULT_CONFIG, ...JSON.parse(stored) })
    } catch { /* ignore */ }
  }, [])

  const set = (key: string, value: string | boolean | number) =>
    setConfig(prev => ({ ...prev, [key]: value }))

  const save = () => {
    localStorage.setItem('soc_config', JSON.stringify(config))
    // Push to window so other hooks can pick it up
    window.dispatchEvent(new CustomEvent('soc-config-updated', { detail: config }))
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
  }

  const reset = () => {
    setConfig(DEFAULT_CONFIG)
    localStorage.removeItem('soc_config')
  }

  const renderField = (field: ConfigField) => {
    const value = config[field.key]

    if (field.type === 'toggle') {
      return (
        <div key={field.key} className="flex items-center justify-between py-3 border-b border-border last:border-0">
          <div>
            <div className="text-sm font-medium text-foreground">{field.label}</div>
            {field.description && <p className="text-xs text-muted-foreground mt-0.5">{field.description}</p>}
          </div>
          <Switch
            checked={!!value}
            onCheckedChange={v => set(field.key, v)}
          />
        </div>
      )
    }

    return (
      <div key={field.key} className="space-y-1.5">
        <div className="flex items-center justify-between">
          <Label htmlFor={field.key} className="text-sm font-medium">{field.label}</Label>
          {field.type === 'text' && String(value).startsWith('http') && (
            <ServicePingBadge url={String(value)} />
          )}
        </div>
        {field.description && (
          <p className="text-xs text-muted-foreground">{field.description}</p>
        )}
        {field.type === 'password' ? (
          <PasswordField
            value={String(value ?? '')}
            onChange={v => set(field.key, v)}
            placeholder={field.placeholder}
          />
        ) : field.type === 'select' ? (
          <Select value={String(value ?? '')} onValueChange={v => set(field.key, v)}>
            <SelectTrigger id={field.key}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {field.options?.map(o => (
                <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        ) : (
          <Input
            id={field.key}
            type={field.type === 'number' ? 'number' : 'text'}
            value={String(value ?? '')}
            onChange={e => set(field.key, field.type === 'number' ? Number(e.target.value) : e.target.value)}
            placeholder={field.placeholder}
            className={field.type === 'number' ? 'w-32' : ''}
          />
        )}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-1">Configuration</h1>
          <p className="text-muted-foreground text-sm">
            Configure API keys, service URLs, LLM settings, and SOAR automation policies
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={reset}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Reset Defaults
          </Button>
          <Button size="sm" onClick={save} className={saved ? 'bg-green-600 hover:bg-green-700' : ''}>
            {saved ? <CheckCircle className="w-4 h-4 mr-2" /> : <Save className="w-4 h-4 mr-2" />}
            {saved ? 'Saved!' : 'Save Changes'}
          </Button>
        </div>
      </div>

      {/* Quick-status strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'LLM Mode',      value: String(config.llm_mode).toUpperCase(),    icon: Bot,    color: 'text-purple-500' },
          { label: 'Environment',   value: String(config.environment).toUpperCase(), icon: Server, color: 'text-blue-500' },
          { label: 'Log Level',     value: String(config.log_level),                 icon: Eye,    color: 'text-yellow-500' },
          { label: 'Auto CRITICAL', value: config.soar_auto_critical ? 'ON' : 'OFF', icon: Zap,    color: config.soar_auto_critical ? 'text-green-500' : 'text-red-500' },
        ].map(item => (
          <Card key={item.label} className="p-3 flex items-center gap-3">
            <item.icon className={`w-5 h-5 ${item.color}`} />
            <div>
              <div className="text-xs text-muted-foreground">{item.label}</div>
              <div className="text-sm font-semibold text-foreground">{item.value}</div>
            </div>
          </Card>
        ))}
      </div>

      {/* Tabs */}
      <Tabs defaultValue="services">
        <TabsList className="flex flex-wrap gap-1 h-auto p-1">
          {Object.entries(SECTIONS).map(([key, section]) => {
            const Icon = TAB_ICONS[key]
            return (
              <TabsTrigger key={key} value={key} className="gap-2 text-xs">
                <Icon className="w-3.5 h-3.5" />
                {section.label}
              </TabsTrigger>
            )
          })}
        </TabsList>

        {Object.entries(SECTIONS).map(([key, section]) => (
          <TabsContent key={key} value={key}>
            <Card className="p-6">
              <div className="mb-5">
                <h2 className="font-semibold text-foreground text-lg">{section.label}</h2>
              </div>
              <div className="space-y-5">
                {section.fields.map(field => renderField(field))}
              </div>
            </Card>
          </TabsContent>
        ))}
      </Tabs>

      {/* .env reference */}
      <Card className="p-4 border-l-4 border-l-yellow-500 bg-yellow-500/5">
        <div className="flex items-start gap-3">
          <Key className="w-4 h-4 text-yellow-500 mt-0.5 flex-shrink-0" />
          <div>
            <div className="text-sm font-medium text-foreground">Backend configuration</div>
            <p className="text-xs text-muted-foreground mt-1">
              These settings are stored in your browser for the UI. For backend services,
              set the corresponding variables in{' '}
              <code className="bg-muted px-1 rounded text-xs">.env</code> at the project root.
              The <code className="bg-muted px-1 rounded text-xs">Save Changes</code> button 
              applies settings to the frontend API client immediately.
            </p>
          </div>
        </div>
      </Card>
    </div>
  )
}
