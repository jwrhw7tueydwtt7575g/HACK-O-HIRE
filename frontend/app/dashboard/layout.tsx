'use client'

import { useEffect, useState } from 'react'
import { QueryProvider } from '@/components/providers'
import { Sidebar } from '@/components/Sidebar'

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const [currentTime, setCurrentTime] = useState<string>('')
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
    const updateTime = () => {
      setCurrentTime(
        new Date().toLocaleDateString('en-US', {
          weekday: 'short',
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        })
      )
    }
    updateTime()
    const interval = setInterval(updateTime, 60000) // Update every minute
    return () => clearInterval(interval)
  }, [])

  return (
    <QueryProvider>
      <div className="flex h-screen bg-background">
        {/* Sidebar */}
        <Sidebar />

        {/* Main content */}
        <main className="flex-1 lg:ml-64 flex flex-col overflow-hidden">
          {/* Top bar */}
          <div className="h-14 border-b border-border flex items-center px-6 bg-card">
            <div className="flex items-center justify-between w-full">
              <div>
                <h2 className="text-lg font-semibold text-foreground">Security Operations Center</h2>
                <p className="text-xs text-muted-foreground">Real-time monitoring and threat detection</p>
              </div>
              <div className="text-xs text-muted-foreground">
                {mounted ? currentTime : '—'}
              </div>
            </div>
          </div>

          {/* Content area */}
          <div className="flex-1 overflow-auto">
            <div className="p-6">
              {children}
            </div>
          </div>
        </main>
      </div>
    </QueryProvider>
  )
}
