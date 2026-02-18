import { useState, useCallback, useEffect } from 'react'
import { INTEGRATIONS } from '@/lib/constants'
import { Integration } from '@/lib/types'

const STORAGE_KEY = 'soc-integrations-state'

export function useIntegrationState() {
  const [integrations, setIntegrations] = useState<Integration[]>([])
  const [isLoaded, setIsLoaded] = useState(false)

  // Load from localStorage on mount
  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored) {
      try {
        const parsed = JSON.parse(stored)
        setIntegrations(parsed)
      } catch (e) {
        console.error('Failed to parse stored integrations', e)
        initializeIntegrations()
      }
    } else {
      initializeIntegrations()
    }
    setIsLoaded(true)
  }, [])

  const initializeIntegrations = () => {
    const initial: Integration[] = INTEGRATIONS.map(int => ({
      ...int,
      status: int.enabled ? 'connected' : 'disconnected',
      lastSync: new Date()
    }))
    setIntegrations(initial)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(initial))
  }

  const toggleIntegration = useCallback((integrationId: string) => {
    setIntegrations(prev => {
      const updated = prev.map(int => {
        if (int.id === integrationId) {
          return {
            ...int,
            enabled: !int.enabled,
            status: !int.enabled ? 'connected' : 'disconnected',
            lastSync: new Date()
          }
        }
        return int
      })
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated))
      return updated
    })
  }, [])

  const updateIntegrationConfig = useCallback((integrationId: string, config: Record<string, unknown>) => {
    setIntegrations(prev => {
      const updated = prev.map(int => {
        if (int.id === integrationId) {
          return {
            ...int,
            config,
            lastSync: new Date()
          }
        }
        return int
      })
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated))
      return updated
    })
  }, [])

  return {
    integrations,
    isLoaded,
    toggleIntegration,
    updateIntegrationConfig
  }
}
