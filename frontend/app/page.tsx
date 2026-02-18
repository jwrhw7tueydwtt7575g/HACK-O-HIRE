'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

export default function Home() {
  const router = useRouter()

  useEffect(() => {
    router.push('/dashboard')
  }, [router])

  return (
    <div className="flex items-center justify-center min-h-screen bg-gradient-to-br from-background via-background to-primary/10">
      <div className="text-center">
        <h1 className="text-4xl font-bold text-foreground mb-4">
          Enterprise Banking SOC Platform
        </h1>
        <p className="text-muted-foreground mb-8">
          Loading dashboard...
        </p>
        <div className="inline-block">
          <div className="w-8 h-8 border-4 border-border border-t-primary rounded-full animate-spin" />
        </div>
      </div>
    </div>
  )
}
