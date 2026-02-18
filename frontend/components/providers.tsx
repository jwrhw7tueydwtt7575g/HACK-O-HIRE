'use client'

import { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

let queryClient: QueryClient

function getQueryClient() {
  if (!queryClient)
    queryClient = new QueryClient({
      defaultOptions: {
        queries: {
          staleTime: 60 * 1000,
        },
      },
    })
  return queryClient
}

export function QueryProvider({ children }: { children: ReactNode }) {
  const client = getQueryClient()

  return (
    <QueryClientProvider client={client}>
      {children}
    </QueryClientProvider>
  )
}
