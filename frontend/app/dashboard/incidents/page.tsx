'use client'

import { Card } from '@/components/ui/card'

export default function IncidentsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground mb-2">Security Incidents</h1>
        <p className="text-muted-foreground">
          Track and manage security incidents across all systems
        </p>
      </div>

      <Card className="p-8 text-center">
        <div className="text-muted-foreground">
          <p className="mb-2">No incidents reported</p>
          <p className="text-sm">All systems are operating normally</p>
        </div>
      </Card>
    </div>
  )
}
