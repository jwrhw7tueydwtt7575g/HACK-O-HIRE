'use client'

import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { AlertTriangle, CheckCircle, Clock, AlertCircle } from 'lucide-react'

const SAMPLE_ALERTS = [
  {
    id: '1',
    severity: 'critical',
    title: 'Suspicious Login Activity Detected',
    description: 'Multiple failed authentication attempts from unusual geographic location',
    minutesAgo: 5,
    source: 'EDR Platform'
  },
  {
    id: '2',
    severity: 'high',
    title: 'Potential Data Exfiltration',
    description: 'Large file transfer to unauthorized external IP address detected',
    minutesAgo: 15,
    source: 'DLP Engine'
  },
  {
    id: '3',
    severity: 'medium',
    title: 'Configuration Change Detected',
    description: 'Unauthorized modification of security policy settings',
    minutesAgo: 30,
    source: 'SIEM System'
  },
  {
    id: '4',
    severity: 'low',
    title: 'Software Update Available',
    description: 'Security patch available for deployed application',
    minutesAgo: 60,
    source: 'Vulnerability Scanner'
  }
]

function formatRelativeTime(minutesAgo: number): string {
  if (minutesAgo < 1) return 'Just now'
  if (minutesAgo < 60) return `${minutesAgo}m ago`
  
  const hoursAgo = Math.floor(minutesAgo / 60)
  if (hoursAgo < 24) return `${hoursAgo}h ago`
  
  const daysAgo = Math.floor(hoursAgo / 24)
  return `${daysAgo}d ago`
}

export default function AlertsPage() {
  const criticalCount = SAMPLE_ALERTS.filter(a => a.severity === 'critical').length
  const highCount = SAMPLE_ALERTS.filter(a => a.severity === 'high').length
  const mediumCount = SAMPLE_ALERTS.filter(a => a.severity === 'medium').length

  const severityConfig = {
    critical: { bg: 'bg-red-500/10', border: 'border-l-red-500', icon: AlertTriangle, color: 'text-red-600 dark:text-red-400' },
    high: { bg: 'bg-orange-500/10', border: 'border-l-orange-500', icon: AlertTriangle, color: 'text-orange-600 dark:text-orange-400' },
    medium: { bg: 'bg-yellow-500/10', border: 'border-l-yellow-500', icon: AlertCircle, color: 'text-yellow-600 dark:text-yellow-400' },
    low: { bg: 'bg-blue-500/10', border: 'border-l-blue-500', icon: CheckCircle, color: 'text-blue-600 dark:text-blue-400' }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-foreground mb-2">Security Alerts</h1>
        <p className="text-muted-foreground">
          Real-time security alerts and threat notifications from all integrated systems
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4 border-l-4 border-l-red-500 bg-red-500/5">
          <div className="text-sm text-muted-foreground">Critical Alerts</div>
          <div className="text-2xl font-bold text-red-600 dark:text-red-400 mt-1">
            {criticalCount}
          </div>
        </Card>
        <Card className="p-4 border-l-4 border-l-orange-500 bg-orange-500/5">
          <div className="text-sm text-muted-foreground">High Priority</div>
          <div className="text-2xl font-bold text-orange-600 dark:text-orange-400 mt-1">
            {highCount}
          </div>
        </Card>
        <Card className="p-4 border-l-4 border-l-yellow-500 bg-yellow-500/5">
          <div className="text-sm text-muted-foreground">Medium Priority</div>
          <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-400 mt-1">
            {mediumCount}
          </div>
        </Card>
        <Card className="p-4 border-l-4 border-l-blue-500 bg-blue-500/5">
          <div className="text-sm text-muted-foreground">Total Alerts</div>
          <div className="text-2xl font-bold text-blue-600 dark:text-blue-400 mt-1">
            {SAMPLE_ALERTS.length}
          </div>
        </Card>
      </div>

      {/* Alerts list */}
      <div className="space-y-3">
        <h2 className="font-semibold text-foreground">Recent Alerts</h2>
        {SAMPLE_ALERTS.map((alert) => {
          const config = severityConfig[alert.severity as keyof typeof severityConfig]
          const IconComponent = config.icon

          return (
            <Card
              key={alert.id}
              className={`p-4 border-l-4 ${config.bg} ${config.border} hover:shadow-md transition-all cursor-pointer`}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3 flex-1">
                  <div className={`p-2 bg-${alert.severity}-500/20 rounded-lg mt-1`}>
                    <IconComponent className={`w-5 h-5 ${config.color}`} />
                  </div>
                  <div className="flex-1">
                    <h3 className="font-semibold text-foreground">{alert.title}</h3>
                    <p className="text-sm text-muted-foreground mt-1">
                      {alert.description}
                    </p>
                    <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                      <span>{alert.source}</span>
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {formatRelativeTime(alert.minutesAgo)}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-1 rounded text-xs font-medium capitalize ${config.color} bg-${alert.severity}-500/10`}>
                    {alert.severity}
                  </span>
                  <Button variant="ghost" size="sm">
                    Investigate
                  </Button>
                </div>
              </div>
            </Card>
          )
        })}
      </div>
    </div>
  )
}
