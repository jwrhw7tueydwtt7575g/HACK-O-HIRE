// Service Health Types
export interface ServiceStatus {
  id: string
  name: string
  icon: string
  status: 'healthy' | 'degraded' | 'down'
  uptime: number
  lastCheck: Date
  dashboardUrl: string
  description: string
}

// Integration Types
export interface Integration {
  id: string
  name: string
  enabled: boolean
  status: 'connected' | 'disconnected' | 'error'
  lastSync: Date
  config?: Record<string, unknown>
}

// File Upload Types
export interface UploadedFile {
  id: string
  name: string
  size: number
  type: string
  progress: number
  status: 'pending' | 'uploading' | 'processing' | 'complete' | 'error'
  uploadedAt: Date
  preview?: string
}

// Pipeline Types
export enum PipelineStage {
  Ingestion = 'ingestion',
  Parsing = 'parsing',
  Enrichment = 'enrichment',
  Detection = 'detection',
  Response = 'response'
}

export interface PipelineMetrics {
  eventsPerSecond: number
  eta: string
  activeAlerts: number
  soarActions: number
}

export interface PipelineStageStatus {
  stage: PipelineStage
  status: 'pending' | 'in-progress' | 'completed' | 'error'
  progress: number
  error?: string
}

export interface PipelineStatus {
  stages: PipelineStageStatus[]
  metrics: PipelineMetrics
  isActive: boolean
  error?: string
}

// Parsing Options Types
export interface ParsingOptions {
  sourceType: string
  timestampFormat: string
  enrichment: boolean
  priority: 'low' | 'medium' | 'high'
}
