'use client'

import { IntegrationSwitcher } from '@/components/dashboard/IntegrationSwitcher'
import { FileUploadCenter } from '@/components/dashboard/FileUploadCenter'
import { ProcessingPipeline } from '@/components/dashboard/ProcessingPipeline'

export default function IntegrationsPage() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-foreground mb-2">Integrations & Processing</h1>
        <p className="text-muted-foreground">
          Manage external integrations, upload files, and monitor processing pipeline
        </p>
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left column - Integrations and File Upload */}
        <div className="lg:col-span-2 space-y-6">
          {/* Integration Management */}
          <IntegrationSwitcher />

          {/* File Upload Center */}
          <FileUploadCenter />
        </div>

        {/* Right column - Pipeline */}
        <div>
          <ProcessingPipeline />
        </div>
      </div>
    </div>
  )
}
