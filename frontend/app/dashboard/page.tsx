'use client'

import { Suspense } from 'react'
import { ServiceStatusCard } from '@/components/dashboard/ServiceStatusCard'
import { SERVICES } from '@/lib/constants'
import { Card } from '@/components/ui/card'

function ServiceGridSkeleton() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {[...Array(9)].map((_, i) => (
        <Card key={i} className="p-4 animate-pulse">
          <div className="h-10 bg-muted rounded mb-3" />
          <div className="space-y-2">
            <div className="h-4 bg-muted rounded w-3/4" />
            <div className="h-4 bg-muted rounded w-1/2" />
          </div>
        </Card>
      ))}
    </div>
  )
}

export default function DashboardPage() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-foreground mb-2">Service Health Status</h1>
        <p className="text-muted-foreground">
          Real-time monitoring of all integrated security services and platforms
        </p>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="p-4 border-l-4 border-l-green-500 bg-green-500/5">
          <div className="text-sm text-muted-foreground">Healthy Services</div>
          <div className="text-2xl font-bold text-green-600 dark:text-green-400">
            {SERVICES.filter(s => s.status === 'healthy').length}
          </div>
        </Card>
        <Card className="p-4 border-l-4 border-l-yellow-500 bg-yellow-500/5">
          <div className="text-sm text-muted-foreground">Degraded Services</div>
          <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
            {SERVICES.filter(s => s.status === 'degraded').length}
          </div>
        </Card>
        <Card className="p-4 border-l-4 border-l-red-500 bg-red-500/5">
          <div className="text-sm text-muted-foreground">Down Services</div>
          <div className="text-2xl font-bold text-red-600 dark:text-red-400">
            {SERVICES.filter(s => s.status === 'down').length}
          </div>
        </Card>
      </div>

      {/* Services grid */}
      <div>
        <h2 className="text-xl font-bold text-foreground mb-4">Services</h2>
        <Suspense fallback={<ServiceGridSkeleton />}>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {SERVICES.map((service) => (
              <ServiceStatusCard key={service.id} baseService={service} />
            ))}
          </div>
        </Suspense>
      </div>
    </div>
  )
}
