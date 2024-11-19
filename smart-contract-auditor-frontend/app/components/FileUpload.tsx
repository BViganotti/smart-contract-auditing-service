import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import LoadingAnimation from './LoadingAnimation'

interface FileUploadProps {
    onFileUpload: (file: File) => void
}

export default function FileUpload({ onFileUpload }: FileUploadProps) {
    const [file, setFile] = useState<File | null>(null)
    const [isDragging, setIsDragging] = useState(false)
    const [error, setError] = useState<string | null>(null)

    const handleDragEnter = (e: React.DragEvent) => {
        e.preventDefault()
        e.stopPropagation()
        setIsDragging(true)
    }

    const handleDragLeave = (e: React.DragEvent) => {
        e.preventDefault()
        e.stopPropagation()
        setIsDragging(false)
    }

    const handleDragOver = (e: React.DragEvent) => {
        e.preventDefault()
        e.stopPropagation()
    }

    const handleDrop = (e: React.DragEvent) => {
        e.preventDefault()
        e.stopPropagation()
        setIsDragging(false)

        const files = e.dataTransfer.files
        if (files && files.length > 0) {
            const file = files[0]
            if (validateFile(file)) {
                setFile(file)
                onFileUpload(file)
            }
        }
    }

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            const file = e.target.files[0]
            if (validateFile(file)) {
                setFile(file)
                onFileUpload(file)
            }
        }
    }

    const validateFile = (file: File): boolean => {
        const validTypes = ['.sol', '.vy', '.json']
        const fileExtension = '.' + file.name.split('.').pop()?.toLowerCase()
        
        if (!validTypes.includes(fileExtension)) {
            setError('Invalid file type. Please upload a Solidity (.sol), Vyper (.vy), or JSON (.json) file.')
            return false
        }
        
        if (file.size > 10 * 1024 * 1024) { // 10MB limit
            setError('File size too large. Please upload a file smaller than 10MB.')
            return false
        }
        
        setError(null)
        return true
    }

    return (
        <div className="w-full">
            <AnimatePresence>
                {error && (
                    <motion.div
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        className="mb-4 p-4 bg-red-500/10 border border-red-500/20 rounded-lg"
                    >
                        <p className="text-red-400 text-sm">{error}</p>
                    </motion.div>
                )}
            </AnimatePresence>

            <motion.div
                className={`relative w-full h-64 ${
                    isDragging ? 'border-indigo-400' : 'border-gray-700'
                } border-2 border-dashed rounded-xl transition-colors duration-200`}
                onDragEnter={handleDragEnter}
                onDragLeave={handleDragLeave}
                onDragOver={handleDragOver}
                onDrop={handleDrop}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
            >
                <input
                    type="file"
                    onChange={handleFileChange}
                    accept=".sol,.vy,.json"
                    className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                />
                
                <div className="absolute inset-0 flex flex-col items-center justify-center p-6">
                    <div className={`w-16 h-16 mb-4 rounded-full flex items-center justify-center ${
                        isDragging ? 'animated-gradient' : 'bg-gray-800'
                    }`}>
                        <svg 
                            className={`w-8 h-8 ${isDragging ? 'text-white' : 'text-gray-400'}`}
                            fill="none" 
                            stroke="currentColor" 
                            viewBox="0 0 24 24"
                        >
                            <path 
                                strokeLinecap="round" 
                                strokeLinejoin="round" 
                                strokeWidth={2} 
                                d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" 
                            />
                        </svg>
                    </div>
                    
                    <div className="text-center">
                        <p className="text-lg text-gray-300 mb-2">
                            {isDragging ? 'Drop your file here' : 'Drag and drop your smart contract'}
                        </p>
                        <p className="text-sm text-gray-500">
                            or <span className="text-indigo-400">browse files</span>
                        </p>
                        <p className="text-xs text-gray-600 mt-2">
                            Supports .sol, .vy, and .json files up to 10MB
                        </p>
                    </div>
                </div>
            </motion.div>

            {file && (
                <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="mt-4 p-4 bg-gray-800/50 rounded-lg flex items-center justify-between"
                >
                    <div className="flex items-center space-x-3">
                        <div className="w-10 h-10 rounded-lg bg-gray-700 flex items-center justify-center">
                            <svg className="w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                            </svg>
                        </div>
                        <div>
                            <p className="text-gray-300 text-sm font-medium">{file.name}</p>
                            <p className="text-gray-500 text-xs">
                                {(file.size / 1024).toFixed(1)} KB
                            </p>
                        </div>
                    </div>
                    <button
                        onClick={() => setFile(null)}
                        className="text-gray-400 hover:text-red-400 transition-colors"
                    >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </motion.div>
            )}
        </div>
    )
}
