'use client'

import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { BarChart3, Download, Calendar } from 'lucide-react'

const REPORTS = [
  {
    name: 'Daily Security Summary',
    description: 'Comprehensive overview of all security events from the past 24 hours',
    date: new Date(Date.now() - 86400000),
    size: '2.4 MB'
  },
  {
    name: 'Weekly Threat Analysis',
    description: 'Detailed threat landscape and vulnerability analysis for the week',
    date: new Date(Date.now() - 604800000),
    size: '5.1 MB'
  },
  {
    name: 'Monthly Compliance Report',
    description: 'Regulatory compliance status and audit trail documentation',
    date: new Date(Date.now() - 2592000000),
    size: '8.7 MB'
  }
]

function formatDate(date: Date): string {
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric'
  })
}

export default function ReportsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground mb-2">Security Reports</h1>
        <p className="text-muted-foreground">
          Generate, view, and manage security analysis reports
        </p>
      </div>

      {/* Generate Report Button */}
      <div className="flex gap-2">
        <Button className="gap-2">
          <BarChart3 className="w-4 h-4" />
          Generate New Report
        </Button>
        <Button variant="outline" className="gap-2">
          <Calendar className="w-4 h-4" />
          Schedule Report
        </Button>
      </div>

      {/* Reports List */}
      <div className="space-y-3">
        <h2 className="font-semibold text-foreground">Available Reports</h2>
        {REPORTS.map((report, index) => (
          <Card
            key={index}
            className="p-4 hover:shadow-md transition-all cursor-pointer"
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <h3 className="font-semibold text-foreground">{report.name}</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  {report.description}
                </p>
                <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                  <span>{formatDate(report.date)}</span>
                  <span>{report.size}</span>
                </div>
              </div>
              <Button
                variant="ghost"
                size="sm"
                className="gap-2"
              >
                <Download className="w-4 h-4" />
                Download
              </Button>
            </div>
          </Card>
        ))}
      </div>
    </div>
  )
}
