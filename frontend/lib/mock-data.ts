import { SERVICES } from './constants'
import { ServiceStatus, PipelineStatus, PipelineStage } from './types'

// Create a fixed reference date to avoid hydration mismatches
const REFERENCE_DATE = new Date('2026-02-18T12:00:00Z')

// Simulate health status variations
export function getSimulatedServiceStatus(baseService: ServiceStatus): ServiceStatus {
  const random = Math.random()
  const status = random > 0.85 ? 'degraded' : random > 0.95 ? 'down' : 'healthy'
  
  // Use fixed reference date instead of new Date() to avoid hydration mismatch
  const lastCheckDate = new Date(REFERENCE_DATE)
  lastCheckDate.setMinutes(lastCheckDate.getMinutes() - Math.floor(Math.random() * 60))
  
  return {
    ...baseService,
    status: status as any,
    uptime: Math.round((99 + Math.random() * 0.99) * 100) / 100,
    lastCheck: lastCheckDate
  }
}

// Generate sample pipeline data
export function generatePipelineStatus(): PipelineStatus {
  const stages = [
    { stage: PipelineStage.Ingestion, status: 'completed' as const, progress: 100 },
    { stage: PipelineStage.Parsing, status: 'completed' as const, progress: 100 },
    { stage: PipelineStage.Enrichment, status: 'in-progress' as const, progress: Math.random() * 100 },
    { stage: PipelineStage.Detection, status: 'pending' as const, progress: 0 },
    { stage: PipelineStage.Response, status: 'pending' as const, progress: 0 }
  ]

  return {
    stages,
    metrics: {
      eventsPerSecond: Math.round(1000 + Math.random() * 5000),
      eta: `${Math.round(5 + Math.random() * 15)} min`,
      activeAlerts: Math.floor(Math.random() * 50),
      soarActions: Math.floor(Math.random() * 10)
    },
    isActive: true
  }
}

// Format timestamp
export function formatTimestamp(date: Date): string {
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })
}

// Get random service for testing
export function getRandomService(): ServiceStatus {
  return SERVICES[Math.floor(Math.random() * SERVICES.length)]
}
