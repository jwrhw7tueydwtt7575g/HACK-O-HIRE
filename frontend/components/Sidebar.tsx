'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { useTheme } from 'next-themes'
import { Button } from '@/components/ui/button'
import { 
  Menu, 
  X, 
  Moon, 
  Sun, 
  BarChart3,
  Shield,
  Database,
  Brain,
  Zap,
  Activity,
  Lock,
  Laptop,
  Radio,
  Key
} from 'lucide-react'

const NAVIGATION_ITEMS = [
  { label: 'Dashboard', href: '/dashboard', icon: BarChart3 },
  { label: 'Alerts', href: '/dashboard/alerts', icon: Activity },
  { label: 'Incidents', href: '/dashboard/incidents', icon: Shield },
  { label: 'Integrations', href: '/dashboard/integrations', icon: Database },
  { label: 'Reports', href: '/dashboard/reports', icon: BarChart3 }
]

const SERVICE_ICONS: Record<string, any> = {
  'Shield': Shield,
  'Database': Database,
  'Brain': Brain,
  'Zap': Zap,
  'Activity': Activity,
  'Lock': Lock,
  'Laptop': Laptop,
  'Radio': Radio,
  'Key': Key
}

export function Sidebar() {
  const [isOpen, setIsOpen] = useState(false)
  const [mounted, setMounted] = useState(false)
  const { theme, setTheme } = useTheme()

  useEffect(() => {
    setMounted(true)
  }, [])

  const toggleTheme = () => {
    setTheme(theme === 'dark' ? 'light' : 'dark')
  }

  // Prevent hydration mismatch by not rendering theme-dependent content until mounted
  if (!mounted) {
    return (
      <>
        <div className="lg:hidden fixed top-4 left-4 z-40">
          <Button
            variant="ghost"
            size="icon"
            className="text-foreground"
            disabled
          >
            <Menu className="w-5 h-5" />
          </Button>
        </div>

        <aside className="fixed left-0 top-0 h-screen w-64 bg-sidebar border-r border-sidebar-border z-30 -translate-x-full lg:translate-x-0">
          <div className="p-6 border-b border-sidebar-border">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div>
                <h1 className="font-bold text-sidebar-foreground">SOC</h1>
                <p className="text-xs text-sidebar-accent-foreground">Platform</p>
              </div>
            </div>
          </div>

          <nav className="p-4 space-y-2">
            {NAVIGATION_ITEMS.map((item) => {
              const Icon = item.icon
              return (
                <Link key={item.href} href={item.href}>
                  <Button
                    variant="ghost"
                    className="w-full justify-start gap-3 text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                    disabled
                  >
                    <Icon className="w-4 h-4" />
                    {item.label}
                  </Button>
                </Link>
              )
            })}
          </nav>

          <div className="flex-1" />

          <div className="p-4 border-t border-sidebar-border space-y-2">
            <Button
              variant="ghost"
              size="icon"
              className="w-full justify-start gap-3 text-sidebar-foreground hover:bg-sidebar-accent"
              disabled
            >
              <Sun className="w-4 h-4" />
              <span className="text-sm">Light Mode</span>
            </Button>
            <div className="text-xs text-sidebar-accent-foreground text-center py-2">
              <p>Enterprise Banking</p>
              <p>SOC Platform v1.0</p>
            </div>
          </div>
        </aside>
      </>
    )
  }

  return (
    <>
      {/* Mobile menu button */}
      <div className="lg:hidden fixed top-4 left-4 z-40">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setIsOpen(!isOpen)}
          className="text-foreground"
        >
          {isOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </Button>
      </div>

      {/* Sidebar */}
      <aside className={`
        fixed left-0 top-0 h-screen w-64 bg-sidebar border-r border-sidebar-border
        transform transition-transform duration-300 ease-in-out z-30
        ${isOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
      `}>
        {/* Header */}
        <div className="p-6 border-b border-sidebar-border">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="font-bold text-sidebar-foreground">SOC</h1>
              <p className="text-xs text-sidebar-accent-foreground">Platform</p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="p-4 space-y-2">
          {NAVIGATION_ITEMS.map((item) => {
            const Icon = item.icon
            return (
              <Link key={item.href} href={item.href}>
                <Button
                  variant="ghost"
                  className="w-full justify-start gap-3 text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                  onClick={() => setIsOpen(false)}
                >
                  <Icon className="w-4 h-4" />
                  {item.label}
                </Button>
              </Link>
            )
          })}
        </nav>

        {/* Spacer */}
        <div className="flex-1" />

        {/* Footer */}
        <div className="p-4 border-t border-sidebar-border space-y-2">
          <Button
            variant="ghost"
            size="icon"
            onClick={toggleTheme}
            className="w-full justify-start gap-3 text-sidebar-foreground hover:bg-sidebar-accent"
          >
            {theme === 'dark' ? (
              <>
                <Sun className="w-4 h-4" />
                <span className="text-sm">Light Mode</span>
              </>
            ) : (
              <>
                <Moon className="w-4 h-4" />
                <span className="text-sm">Dark Mode</span>
              </>
            )}
          </Button>
          <div className="text-xs text-sidebar-accent-foreground text-center py-2">
            <p>Enterprise Banking</p>
            <p>SOC Platform v1.0</p>
          </div>
        </div>
      </aside>

      {/* Overlay for mobile */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-20 lg:hidden"
          onClick={() => setIsOpen(false)}
        />
      )}
    </>
  )
}
