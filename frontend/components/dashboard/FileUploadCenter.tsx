'use client'

import { useRef, useState, useCallback } from 'react'
import { useFileUpload } from '@/hooks/useFileUpload'
import { UploadedFile, ParsingOptions } from '@/lib/types'
import { ALLOWED_FILE_TYPES, MAX_FILE_SIZE } from '@/lib/constants'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogTrigger } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Upload,
  File,
  Trash2,
  Play,
  Pause,
  Eye,
  Settings,
  CheckCircle,
  AlertCircle,
  Loader2
} from 'lucide-react'
import { cn } from '@/lib/utils'

function FilePreviewDialog({ file }: { file: UploadedFile }) {
  const [preview, setPreview] = useState<string>('')
  const [isLoading, setIsLoading] = useState(false)

  const loadPreview = useCallback(() => {
    setIsLoading(true)
    // Simulate loading file preview
    setTimeout(() => {
      setPreview(
        `File: ${file.name}\nSize: ${(file.size / 1024 / 1024).toFixed(2)} MB\n\n[File preview would show first 100 lines of content here]`
      )
      setIsLoading(false)
    }, 500)
  }, [file])

  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="h-8 px-2"
          onClick={loadPreview}
        >
          <Eye className="w-3 h-3" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Preview: {file.name}</DialogTitle>
          <DialogDescription>
            View the first 100 lines of your uploaded file
          </DialogDescription>
        </DialogHeader>
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-5 h-5 animate-spin" />
          </div>
        ) : (
          <div className="bg-muted p-4 rounded font-mono text-xs whitespace-pre-wrap max-h-96 overflow-auto">
            {preview}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

function ParsingOptionsDialog({
  file,
  onProcess
}: {
  file: UploadedFile
  onProcess: (options: ParsingOptions) => void
}) {
  const [options, setOptions] = useState<ParsingOptions>({
    sourceType: 'log',
    timestampFormat: 'ISO8601',
    enrichment: true,
    priority: 'medium'
  })

  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm" className="h-8 px-2">
          <Settings className="w-3 h-3" />
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Parsing Options: {file.name}</DialogTitle>
          <DialogDescription>
            Configure how this file should be parsed and processed
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label htmlFor="source-type">Source Type</Label>
            <Select value={options.sourceType} onValueChange={(value) => setOptions({ ...options, sourceType: value })}>
              <SelectTrigger id="source-type" className="mt-1">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="log">System Log</SelectItem>
                <SelectItem value="json">JSON</SelectItem>
                <SelectItem value="csv">CSV</SelectItem>
                <SelectItem value="evtx">Windows Event</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div>
            <Label htmlFor="timestamp">Timestamp Format</Label>
            <Select value={options.timestampFormat} onValueChange={(value) => setOptions({ ...options, timestampFormat: value })}>
              <SelectTrigger id="timestamp" className="mt-1">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ISO8601">ISO 8601</SelectItem>
                <SelectItem value="unix">Unix Epoch</SelectItem>
                <SelectItem value="custom">Custom</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div>
            <Label htmlFor="priority">Priority</Label>
            <Select value={options.priority} onValueChange={(value) => setOptions({ ...options, priority: value as any })}>
              <SelectTrigger id="priority" className="mt-1">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="high">High</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="enrichment"
              checked={options.enrichment}
              onChange={(e) => setOptions({ ...options, enrichment: e.target.checked })}
              className="w-4 h-4"
            />
            <Label htmlFor="enrichment" className="cursor-pointer">
              Enable Data Enrichment
            </Label>
          </div>

          <Button
            className="w-full"
            onClick={() => onProcess(options)}
          >
            Start Processing
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

function FileItem({
  file,
  onRemove,
  onPause,
  onResume,
  onProcess
}: {
  file: UploadedFile
  onRemove: (id: string) => void
  onPause: (id: string) => void
  onResume: (id: string) => void
  onProcess: (id: string, options: ParsingOptions) => void
}) {
  return (
    <div className="border border-border rounded-lg p-3 hover:bg-muted/50 transition-colors">
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-start gap-3 flex-1">
          <div className="p-2 bg-primary/10 rounded">
            <File className="w-4 h-4 text-primary" />
          </div>
          <div className="flex-1 min-w-0">
            <h4 className="font-medium text-foreground text-sm truncate">{file.name}</h4>
            <p className="text-xs text-muted-foreground">
              {(file.size / 1024 / 1024).toFixed(2)} MB
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1">
          {file.status === 'complete' && (
            <CheckCircle className="w-4 h-4 text-green-500" />
          )}
          {file.status === 'error' && (
            <AlertCircle className="w-4 h-4 text-red-500" />
          )}
          {file.status === 'processing' && (
            <Loader2 className="w-4 h-4 animate-spin text-blue-500" />
          )}
        </div>
      </div>

      {/* Progress bar */}
      <Progress value={file.progress} className="mb-3 h-1.5" />

      {/* Status and actions */}
      <div className="flex items-center justify-between text-xs">
        <span className="text-muted-foreground capitalize">{file.status}</span>

        <div className="flex items-center gap-1">
          <FilePreviewDialog file={file} />
          {file.status === 'uploading' && (
            <Button
              variant="ghost"
              size="sm"
              className="h-8 px-2"
              onClick={() => onPause(file.id)}
            >
              <Pause className="w-3 h-3" />
            </Button>
          )}
          {file.status === 'pending' && (
            <Button
              variant="ghost"
              size="sm"
              className="h-8 px-2"
              onClick={() => onResume(file.id)}
            >
              <Play className="w-3 h-3" />
            </Button>
          )}
          {file.status === 'complete' && (
            <ParsingOptionsDialog
              file={file}
              onProcess={(options) => onProcess(file.id, options)}
            />
          )}
          <Button
            variant="ghost"
            size="sm"
            className="h-8 px-2 text-destructive hover:text-destructive"
            onClick={() => onRemove(file.id)}
          >
            <Trash2 className="w-3 h-3" />
          </Button>
        </div>
      </div>
    </div>
  )
}

export function FileUploadCenter() {
  const { files, totalSize, addFiles, updateFileProgress, removeFile, pauseFile, resumeFile } = useFileUpload()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [isDragging, setIsDragging] = useState(false)

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(true)
  }

  const handleDragLeave = () => {
    setIsDragging(false)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
    const droppedFiles = Array.from(e.dataTransfer.files)
    const validFiles = droppedFiles.filter(f => {
      const ext = '.' + f.name.split('.').pop()?.toLowerCase()
      return ALLOWED_FILE_TYPES.includes(ext) && f.size <= MAX_FILE_SIZE
    })
    addFiles(validFiles)

    // Simulate upload
    validFiles.forEach(file => {
      const uploadedFile = files.find(f => f.name === file.name)
      if (uploadedFile) {
        let progress = 0
        const interval = setInterval(() => {
          progress += Math.random() * 30
          if (progress >= 100) {
            progress = 100
            clearInterval(interval)
            updateFileProgress(uploadedFile.id, 100, 'complete')
          } else {
            updateFileProgress(uploadedFile.id, progress, 'uploading')
          }
        }, 800)
      }
    })
  }

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = Array.from(e.target.files || [])
    addFiles(selectedFiles)
  }

  const handleProcess = (_fileId: string, _options: ParsingOptions) => {
    // Would process the file with given options
    updateFileProgress(_fileId, 100, 'processing')
  }

  const allowedTypesDisplay = ALLOWED_FILE_TYPES.join(', ')

  return (
    <Card className="p-4 space-y-4">
      <div>
        <h3 className="font-semibold text-foreground mb-1">File Upload Center</h3>
        <p className="text-xs text-muted-foreground">
          Supported formats: {allowedTypesDisplay} (Max 500MB)
        </p>
      </div>

      {/* Drag and drop area */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={cn(
          'border-2 border-dashed rounded-lg p-8 text-center transition-colors',
          isDragging
            ? 'border-primary bg-primary/5'
            : 'border-border hover:border-primary/50'
        )}
      >
        <Upload className="w-8 h-8 mx-auto mb-2 text-muted-foreground" />
        <p className="text-sm font-medium text-foreground mb-1">
          Drag and drop files here
        </p>
        <p className="text-xs text-muted-foreground mb-4">
          or click to browse
        </p>
        <Button
          variant="outline"
          size="sm"
          onClick={() => fileInputRef.current?.click()}
        >
          Browse Files
        </Button>
        <input
          ref={fileInputRef}
          type="file"
          multiple
          hidden
          onChange={handleFileSelect}
          accept={ALLOWED_FILE_TYPES.join(',')}
        />
      </div>

      {/* File queue */}
      {files.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="text-sm font-medium text-foreground">
              {files.length} file{files.length !== 1 ? 's' : ''} queued
            </div>
            <div className="text-xs text-muted-foreground">
              Total: {(totalSize / 1024 / 1024).toFixed(2)} MB
            </div>
          </div>

          <div className="space-y-2 max-h-96 overflow-y-auto">
            {files.map(file => (
              <FileItem
                key={file.id}
                file={file}
                onRemove={removeFile}
                onPause={pauseFile}
                onResume={resumeFile}
                onProcess={handleProcess}
              />
            ))}
          </div>
        </div>
      )}
    </Card>
  )
}
