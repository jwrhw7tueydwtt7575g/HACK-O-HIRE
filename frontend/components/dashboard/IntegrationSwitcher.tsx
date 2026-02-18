'use client'

import { useState } from 'react'
import { useIntegrationState } from '@/hooks/useIntegrationState'
import { Integration } from '@/lib/types'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogTrigger } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Settings, CheckCircle, AlertCircle } from 'lucide-react'
import { formatTimestamp } from '@/lib/mock-data'
import { cn } from '@/lib/utils'

interface IntegrationSwitcherProps {
  integration: Integration
  onToggle: (id: string) => void
  onUpdateConfig: (id: string, config: Record<string, unknown>) => void
}

function IntegrationConfigDialog({ 
  integration, 
  onUpdateConfig 
}: { 
  integration: Integration
  onUpdateConfig: (id: string, config: Record<string, unknown>) => void
}) {
  const [config, setConfig] = useState<Record<string, string>>(
    (integration.config as Record<string, string>) || { apiKey: '', webhookUrl: '' }
  )

  const handleSave = () => {
    onUpdateConfig(integration.id, config)
  }

  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm" className="h-8 px-2">
          <Settings className="w-3 h-3" />
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Configure {integration.name}</DialogTitle>
          <DialogDescription>
            Enter your API credentials and webhook settings for {integration.name}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label htmlFor="api-key">API Key</Label>
            <Input
              id="api-key"
              placeholder="Enter API key"
              value={config.apiKey || ''}
              onChange={(e) => setConfig({ ...config, apiKey: e.target.value })}
              className="mt-1"
            />
          </div>
          <div>
            <Label htmlFor="webhook">Webhook URL</Label>
            <Input
              id="webhook"
              placeholder="https://example.com/webhook"
              value={config.webhookUrl || ''}
              onChange={(e) => setConfig({ ...config, webhookUrl: e.target.value })}
              className="mt-1"
            />
          </div>
          <Button onClick={handleSave} className="w-full">
            Save Configuration
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

function IntegrationItem({ 
  integration, 
  onToggle, 
  onUpdateConfig 
}: IntegrationSwitcherProps) {
  return (
    <div className="flex items-center justify-between p-3 border border-border rounded-lg hover:bg-muted/50 transition-colors">
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <h4 className="font-medium text-foreground text-sm">{integration.name}</h4>
          {integration.status === 'connected' && (
            <CheckCircle className="w-4 h-4 text-green-500" />
          )}
          {integration.status === 'error' && (
            <AlertCircle className="w-4 h-4 text-red-500" />
          )}
        </div>
        <p className="text-xs text-muted-foreground mt-1">
          Last sync: {formatTimestamp(integration.lastSync)}
        </p>
      </div>

      <div className="flex items-center gap-2">
        <IntegrationConfigDialog 
          integration={integration} 
          onUpdateConfig={onUpdateConfig} 
        />
        <Switch
          checked={integration.enabled}
          onCheckedChange={() => onToggle(integration.id)}
        />
      </div>
    </div>
  )
}

export function IntegrationSwitcher() {
  const { integrations, isLoaded, toggleIntegration, updateIntegrationConfig } = useIntegrationState()

  if (!isLoaded) {
    return (
      <Card className="p-4">
        <div className="animate-pulse">
          <div className="h-4 bg-muted rounded w-1/4 mb-4" />
          <div className="space-y-2">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-12 bg-muted rounded" />
            ))}
          </div>
        </div>
      </Card>
    )
  }

  const enabledCount = integrations.filter(i => i.enabled).length

  return (
    <Card className="p-4">
      <div className="mb-4">
        <h3 className="font-semibold text-foreground mb-1">Integration Status</h3>
        <p className="text-xs text-muted-foreground">
          {enabledCount} of {integrations.length} integrations active
        </p>
      </div>

      <div className="space-y-2">
        {integrations.map((integration) => (
          <IntegrationItem
            key={integration.id}
            integration={integration}
            onToggle={toggleIntegration}
            onUpdateConfig={updateIntegrationConfig}
          />
        ))}
      </div>

      {/* Summary stats */}
      <div className="mt-4 pt-4 border-t border-border">
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div className="p-2 bg-green-500/10 rounded">
            <div className="text-green-700 dark:text-green-400 font-medium">
              {integrations.filter(i => i.status === 'connected').length}
            </div>
            <div className="text-muted-foreground">Connected</div>
          </div>
          <div className="p-2 bg-yellow-500/10 rounded">
            <div className="text-yellow-700 dark:text-yellow-400 font-medium">
              {integrations.filter(i => !i.enabled).length}
            </div>
            <div className="text-muted-foreground">Disabled</div>
          </div>
        </div>
      </div>
    </Card>
  )
}
