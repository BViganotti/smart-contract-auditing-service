'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import FileUpload from './components/FileUpload'
import LoadingAnimation from './components/LoadingAnimation'
import Results from './components/Results'

export default function Home() {
  const [file, setFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState<any>(null)

  const handleFileUpload = async (uploadedFile: File) => {
    setFile(uploadedFile)
    setLoading(true)
    
    const formData = new FormData()
    formData.append('contract', uploadedFile)

    try {
      const response = await fetch('/api/audit', {
        method: 'POST',
        body: formData,
      })
      const data = await response.json()
      setResults(data)
    } catch (error) {
      console.error('Error:', error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="min-h-screen flex flex-col bg-[#0f172a]">
      {/* Header */}
      <motion.div 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full py-6 px-8 flex items-center justify-between border-b border-gray-800"
      >
        <div className="flex items-center space-x-4">
          <div className="w-10 h-10 rounded-lg animated-gradient flex items-center justify-center">
            <span className="text-2xl">🔒</span>
          </div>
          <h1 className="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-purple-400">
            Smart Contract Auditor
          </h1>
        </div>
        <div className="flex items-center space-x-4">
          <a 
            href="https://github.com/yourusername/smart-contract-auditor" 
            target="_blank"
            rel="noopener noreferrer"
            className="text-gray-400 hover:text-white transition-colors"
          >
            <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
              <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.604-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
            </svg>
          </a>
        </div>
      </motion.div>

      {/* Main Content */}
      <div className="flex-1 container mx-auto px-4 py-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="max-w-5xl mx-auto"
        >
          {!results && (
            <div className="text-center mb-12">
              <h2 className="text-4xl font-bold text-white mb-4">
                Secure Your Smart Contracts
              </h2>
              <p className="text-gray-400 text-lg max-w-2xl mx-auto">
                Upload your smart contract for a comprehensive security analysis. 
                We'll identify vulnerabilities and provide actionable recommendations.
              </p>
            </div>
          )}

          <div className={`glass-card ${results ? 'p-0' : 'p-8'}`}>
            {!results && <FileUpload onFileUpload={handleFileUpload} />}
            {loading && (
              <div className="flex flex-col items-center justify-center p-12">
                <LoadingAnimation />
                <p className="text-gray-400 mt-4">Analyzing your smart contract...</p>
              </div>
            )}
            {results && <Results data={results} />}
          </div>
        </motion.div>
      </div>

      {/* Footer */}
      <footer className="w-full py-4 px-8 border-t border-gray-800">
        <div className="container mx-auto flex justify-between items-center">
          <p className="text-gray-500 text-sm">
            2024 Smart Contract Auditor. All rights reserved.
          </p>
          <div className="flex space-x-6">
            <a href="#" className="text-gray-500 hover:text-gray-400 text-sm">Privacy Policy</a>
            <a href="#" className="text-gray-500 hover:text-gray-400 text-sm">Terms of Service</a>
            <a href="#" className="text-gray-500 hover:text-gray-400 text-sm">Documentation</a>
          </div>
        </div>
      </footer>
    </main>
  )
}
