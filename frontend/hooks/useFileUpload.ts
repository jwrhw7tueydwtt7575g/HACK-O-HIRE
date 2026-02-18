import { useState, useCallback } from 'react'
import { UploadedFile } from '@/lib/types'
import { ALLOWED_FILE_TYPES, MAX_FILE_SIZE } from '@/lib/constants'

export function useFileUpload() {
  const [files, setFiles] = useState<UploadedFile[]>([])
  const [totalSize, setTotalSize] = useState(0)

  const addFiles = useCallback((newFiles: File[]) => {
    const validFiles: UploadedFile[] = []
    let newTotalSize = totalSize

    for (const file of newFiles) {
      // Check file type
      const extension = '.' + file.name.split('.').pop()?.toLowerCase()
      if (!ALLOWED_FILE_TYPES.includes(extension)) {
        console.warn(`File type ${extension} not allowed`)
        continue
      }

      // Check file size
      if (file.size > MAX_FILE_SIZE) {
        console.warn(`File ${file.name} exceeds max size of 500MB`)
        continue
      }

      const newFile: UploadedFile = {
        id: Math.random().toString(36).substr(2, 9),
        name: file.name,
        size: file.size,
        type: file.type || 'application/octet-stream',
        progress: 0,
        status: 'pending',
        uploadedAt: new Date()
      }

      validFiles.push(newFile)
      newTotalSize += file.size
    }

    setFiles(prev => [...prev, ...validFiles])
    setTotalSize(newTotalSize)
    return validFiles
  }, [totalSize])

  const updateFileProgress = useCallback((fileId: string, progress: number, status: UploadedFile['status']) => {
    setFiles(prev =>
      prev.map(file =>
        file.id === fileId ? { ...file, progress, status } : file
      )
    )
  }, [])

  const removeFile = useCallback((fileId: string) => {
    setFiles(prev => {
      const file = prev.find(f => f.id === fileId)
      if (file) {
        setTotalSize(prev => prev - file.size)
      }
      return prev.filter(f => f.id !== fileId)
    })
  }, [])

  const clearCompleted = useCallback(() => {
    setFiles(prev => {
      const toKeep = prev.filter(f => f.status !== 'complete')
      const removed = prev.filter(f => f.status === 'complete')
      
      let newSize = totalSize
      removed.forEach(f => {
        newSize -= f.size
      })
      setTotalSize(newSize)
      
      return toKeep
    })
  }, [totalSize])

  const pauseFile = useCallback((fileId: string) => {
    setFiles(prev =>
      prev.map(file =>
        file.id === fileId ? { ...file, status: 'pending' } : file
      )
    )
  }, [])

  const resumeFile = useCallback((fileId: string) => {
    setFiles(prev =>
      prev.map(file =>
        file.id === fileId ? { ...file, status: 'uploading' } : file
      )
    )
  }, [])

  return {
    files,
    totalSize,
    addFiles,
    updateFileProgress,
    removeFile,
    clearCompleted,
    pauseFile,
    resumeFile
  }
}
