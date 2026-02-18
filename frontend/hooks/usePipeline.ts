import { useState, useEffect, useCallback } from 'react'
import { PipelineStatus, PipelineStage } from '@/lib/types'
import { generatePipelineStatus } from '@/lib/mock-data'

export function usePipeline() {
  const [pipelineStatus, setPipelineStatus] = useState<PipelineStatus | null>(null)
  const [isActive, setIsActive] = useState(false)

  // Simulate WebSocket connection or polling
  useEffect(() => {
    if (!isActive) return

    // Initial status
    setPipelineStatus(generatePipelineStatus())

    // Simulate updates every 2 seconds
    const interval = setInterval(() => {
      setPipelineStatus(prev => {
        if (!prev) return null

        const newStatus = generatePipelineStatus()
        
        // Simulate progression through stages
        const completedStages = prev.stages.filter(s => s.status === 'completed').length
        
        return {
          ...newStatus,
          stages: prev.stages.map((stage, idx) => {
            if (idx < completedStages) {
              return { ...stage, status: 'completed' as const, progress: 100 }
            } else if (idx === completedStages) {
              return {
                ...stage,
                status: 'in-progress' as const,
                progress: Math.min(95, stage.progress + Math.random() * 15)
              }
            }
            return stage
          })
        }
      })
    }, 2000)

    return () => clearInterval(interval)
  }, [isActive])

  const startPipeline = useCallback(() => {
    setIsActive(true)
    setPipelineStatus(generatePipelineStatus())
  }, [])

  const stopPipeline = useCallback(() => {
    setIsActive(false)
  }, [])

  const resetPipeline = useCallback(() => {
    setPipelineStatus(null)
    setIsActive(false)
  }, [])

  return {
    pipelineStatus,
    isActive,
    startPipeline,
    stopPipeline,
    resetPipeline
  }
}
