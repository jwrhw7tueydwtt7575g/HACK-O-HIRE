'use client'

import { ServiceStatus } from '@/lib/types'
import { useServiceHealth } from '@/hooks/useServiceHealth'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { ExternalLink, Loader2 } from 'lucide-react'
import { 
  Shield,
  Database,
  Brain,
  Zap,
  Activity,
  Lock,
  Laptop,
  Radio,
  Key
} from 'lucide-react'
import { formatTimestamp } from '@/lib/mock-data'
import { cn } from '@/lib/utils'

const ICON_MAP: Record<string, React.ComponentType<{ className?: string }>> = {
  'Shield': Shield,
  'Database': Database,
  'Brain': Brain,
  'Zap': Zap,
  'Activity': Activity,
  'Lock': Lock,
  'Laptop': Laptop,
  'Radio': Radio,
  'Key': Key
}

interface ServiceStatusCardProps {
  baseService: ServiceStatus
}

export function ServiceStatusCard({ baseService }: ServiceStatusCardProps) {
  const { data: service, isLoading } = useServiceHealth(baseService.id)
  const displayService = service || baseService

  const IconComponent = ICON_MAP[baseService.icon] || Shield

  const statusColor = {
    healthy: 'bg-green-500',
    degraded: 'bg-yellow-500',
    down: 'bg-red-500'
  }[displayService.status]

  const statusBg = {
    healthy: 'bg-green-500/10',
    degraded: 'bg-yellow-500/10',
    down: 'bg-red-500/10'
  }[displayService.status]

  return (
    <Card className={cn(
      'p-4 border-l-4 hover:shadow-lg transition-all duration-300',
      statusBg,
      displayService.status === 'healthy' && 'border-l-green-500',
      displayService.status === 'degraded' && 'border-l-yellow-500',
      displayService.status === 'down' && 'border-l-red-500'
    )}>
      {/* Header with icon and status */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/10 rounded-lg">
            <IconComponent className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h3 className="font-semibold text-foreground">{displayService.name}</h3>
            <p className="text-xs text-muted-foreground">{baseService.description}</p>
          </div>
        </div>
        <div className={cn(
          'w-3 h-3 rounded-full animate-pulse',
          statusColor
        )} />
      </div>

      {/* Status and metrics */}
      <div className="space-y-2 mb-4">
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">Status:</span>
          <span className={cn(
            'font-medium capitalize px-2 py-1 rounded text-xs',
            displayService.status === 'healthy' && 'bg-green-500/20 text-green-700 dark:text-green-400',
            displayService.status === 'degraded' && 'bg-yellow-500/20 text-yellow-700 dark:text-yellow-400',
            displayService.status === 'down' && 'bg-red-500/20 text-red-700 dark:text-red-400'
          )}>
            {displayService.status}
          </span>
        </div>

        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">Uptime:</span>
          <span className="font-medium">{displayService.uptime}%</span>
        </div>

        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>Last check:</span>
          <span>{formatTimestamp(displayService.lastCheck)}</span>
        </div>
      </div>

      {/* Uptime progress bar */}
      <div className="mb-4 h-1.5 bg-muted rounded-full overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-blue-500 to-purple-600 transition-all duration-500"
          style={{ width: `${displayService.uptime}%` }}
        />
      </div>

      {/* Action button */}
      <Button
        asChild
        size="sm"
        variant="outline"
        className="w-full text-xs h-8"
      >
        <a href={displayService.dashboardUrl} target="_blank" rel="noopener noreferrer">
          {isLoading ? (
            <>
              <Loader2 className="w-3 h-3 mr-1 animate-spin" />
              Loading...
            </>
          ) : (
            <>
              <ExternalLink className="w-3 h-3 mr-1" />
              View Dashboard
            </>
          )}
        </a>
      </Button>
    </Card>
  )
}
