import { useQuery } from '@tanstack/react-query'
import { SERVICES } from '@/lib/constants'
import { ServiceStatus } from '@/lib/types'
import { getSimulatedServiceStatus } from '@/lib/mock-data'

// Create initial data synchronously to avoid hydration mismatch
const initialServiceData: Record<string, ServiceStatus> = {}

SERVICES.forEach(service => {
  initialServiceData[service.id] = getSimulatedServiceStatus(service)
})

async function fetchServiceHealth(serviceId: string): Promise<ServiceStatus> {
  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 300 + Math.random() * 200))
  
  const baseService = SERVICES.find(s => s.id === serviceId)
  if (!baseService) throw new Error(`Service ${serviceId} not found`)
  
  return getSimulatedServiceStatus(baseService)
}

export function useServiceHealth(serviceId: string) {
  const initialData = initialServiceData[serviceId]
  
  return useQuery({
    queryKey: ['service-health', serviceId],
    queryFn: () => fetchServiceHealth(serviceId),
    initialData,
    refetchInterval: 30000, // Poll every 30 seconds
    staleTime: 20000,
    gcTime: 5 * 60 * 1000 // 5 minutes
  })
}

export function useAllServicesHealth() {
  const initialData = Object.values(initialServiceData)
  
  return useQuery({
    queryKey: ['all-services-health'],
    queryFn: async () => {
      await new Promise(resolve => setTimeout(resolve, 300))
      return SERVICES.map(getSimulatedServiceStatus)
    },
    initialData,
    refetchInterval: 30000,
    staleTime: 20000,
    gcTime: 5 * 60 * 1000
  })
}
