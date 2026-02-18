'use client'

import { usePipeline } from '@/hooks/usePipeline'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { motion } from 'framer-motion'
import {
  Play,
  Square,
  RotateCcw,
  Upload,
  FileText,
  Layers,
  AlertTriangle,
  CheckCircle,
  Zap,
  Clock,
  AlertCircle
} from 'lucide-react'
import { cn } from '@/lib/utils'

const STAGE_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  'upload': Upload,
  'file-text': FileText,
  'layers': Layers,
  'alert-triangle': AlertTriangle,
  'check-circle': CheckCircle,
}

export function ProcessingPipeline() {
  const { pipelineStatus, isActive, startPipeline, stopPipeline, resetPipeline } = usePipeline()

  if (!pipelineStatus && !isActive) {
    return (
      <Card className="p-4">
        <div className="space-y-4">
          <div>
            <h3 className="font-semibold text-foreground mb-1">Processing Pipeline</h3>
            <p className="text-xs text-muted-foreground">
              Start processing to view real-time pipeline status
            </p>
          </div>
          <Button onClick={startPipeline} className="w-full gap-2">
            <Play className="w-4 h-4" />
            Start Pipeline
          </Button>
        </div>
      </Card>
    )
  }

  if (!pipelineStatus) return null

  return (
    <Card className="p-4 space-y-6">
      {/* Header with controls */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="font-semibold text-foreground">Processing Pipeline</h3>
          <p className="text-xs text-muted-foreground">
            {isActive ? 'Pipeline is running' : 'Pipeline completed'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {isActive && (
            <Button
              size="sm"
              variant="outline"
              onClick={stopPipeline}
              className="gap-2"
            >
              <Square className="w-3 h-3" />
              Stop
            </Button>
          )}
          <Button
            size="sm"
            variant="outline"
            onClick={resetPipeline}
            className="gap-2"
          >
            <RotateCcw className="w-3 h-3" />
            Reset
          </Button>
        </div>
      </div>

      {/* Pipeline stages */}
      <div className="space-y-3">
        {pipelineStatus.stages.map((stage, index) => {
          const isCompleted = stage.status === 'completed'
          const isInProgress = stage.status === 'in-progress'
          const isError = stage.status === 'error'
          const isPending = stage.status === 'pending'

          const stageNames: Record<string, string> = {
            'ingestion': 'Ingestion',
            'parsing': 'Parsing',
            'enrichment': 'Enrichment',
            'detection': 'Detection',
            'response': 'Response'
          }

          const stageIcons: Record<string, string> = {
            'ingestion': 'upload',
            'parsing': 'file-text',
            'enrichment': 'layers',
            'detection': 'alert-triangle',
            'response': 'check-circle'
          }

          const IconComponent = STAGE_ICONS[stageIcons[stage.stage]] || Upload

          return (
            <div key={stage.stage}>
              {/* Stage box */}
              <motion.div
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                className={cn(
                  'p-3 rounded-lg border transition-all',
                  isCompleted && 'bg-green-500/10 border-green-500/30',
                  isInProgress && 'bg-blue-500/10 border-blue-500/30',
                  isError && 'bg-red-500/10 border-red-500/30',
                  isPending && 'bg-muted border-border'
                )}
              >
                <div className="flex items-center gap-3 mb-2">
                  <div className={cn(
                    'p-2 rounded-lg',
                    isCompleted && 'bg-green-500/20',
                    isInProgress && 'bg-blue-500/20',
                    isError && 'bg-red-500/20',
                    isPending && 'bg-muted'
                  )}>
                    {isCompleted && (
                      <motion.div
                        initial={{ scale: 0 }}
                        animate={{ scale: 1 }}
                        transition={{ type: 'spring' }}
                      >
                        <CheckCircle className="w-4 h-4 text-green-600 dark:text-green-400" />
                      </motion.div>
                    )}
                    {isInProgress && (
                      <motion.div
                        animate={{ rotate: 360 }}
                        transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
                      >
                        <Zap className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                      </motion.div>
                    )}
                    {isError && (
                      <AlertCircle className="w-4 h-4 text-red-600 dark:text-red-400" />
                    )}
                    {isPending && (
                      <IconComponent className="w-4 h-4 text-muted-foreground" />
                    )}
                  </div>

                  <div className="flex-1">
                    <h4 className="font-medium text-sm text-foreground">
                      {stageNames[stage.stage]}
                    </h4>
                    <p className="text-xs text-muted-foreground capitalize">
                      {stage.status}
                      {stage.error && ` - ${stage.error}`}
                    </p>
                  </div>

                  <div className="text-sm font-semibold">
                    {isCompleted ? '100%' : `${Math.round(stage.progress)}%`}
                  </div>
                </div>

                {/* Progress bar */}
                <div className="w-full h-1.5 bg-muted rounded-full overflow-hidden">
                  <motion.div
                    className={cn(
                      'h-full transition-all',
                      isCompleted && 'bg-green-500',
                      isInProgress && 'bg-gradient-to-r from-blue-500 to-purple-500',
                      isError && 'bg-red-500',
                      isPending && 'bg-muted-foreground/20'
                    )}
                    initial={{ width: 0 }}
                    animate={{ width: `${Math.min(stage.progress, 100)}%` }}
                    transition={{ duration: 0.5 }}
                  />
                </div>
              </motion.div>

              {/* Arrow between stages */}
              {index < pipelineStatus.stages.length - 1 && (
                <div className="flex justify-center py-2">
                  <motion.div
                    animate={isCompleted ? { y: [0, 4, 0] } : {}}
                    transition={{ duration: 1.5, repeat: Infinity }}
                  >
                    <div className="w-0.5 h-4 bg-gradient-to-b from-border to-transparent" />
                  </motion.div>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 pt-4 border-t border-border">
        <div className="text-center">
          <div className="text-xs text-muted-foreground">Events/sec</div>
          <div className="text-lg font-bold text-foreground">
            {pipelineStatus.metrics.eventsPerSecond.toLocaleString()}
          </div>
        </div>
        <div className="text-center">
          <div className="text-xs text-muted-foreground flex items-center justify-center gap-1">
            <Clock className="w-3 h-3" />
            ETA
          </div>
          <div className="text-lg font-bold text-foreground">
            {pipelineStatus.metrics.eta}
          </div>
        </div>
        <div className="text-center">
          <div className="text-xs text-muted-foreground">Active Alerts</div>
          <div className="text-lg font-bold text-orange-600 dark:text-orange-400">
            {pipelineStatus.metrics.activeAlerts}
          </div>
        </div>
        <div className="text-center">
          <div className="text-xs text-muted-foreground">SOAR Actions</div>
          <div className="text-lg font-bold text-blue-600 dark:text-blue-400">
            {pipelineStatus.metrics.soarActions}
          </div>
        </div>
      </div>
    </Card>
  )
}
