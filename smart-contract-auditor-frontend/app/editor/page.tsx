'use client';

import { useState } from 'react';
import Editor from '@monaco-editor/react';
import { motion } from 'framer-motion';
import { useRouter } from 'next/navigation';

export default function EditorPage() {
  const router = useRouter();
  const [code, setCode] = useState<string>(`// Write or paste your Solidity contract here
contract MyContract {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }
}
`);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleEditorChange = (value: string | undefined) => {
    if (value) setCode(value);
    if (error) setError(null);
  };

  const handleAnalyze = async () => {
    try {
      setLoading(true);
      setError(null);

      const formData = new FormData();
      const blob = new Blob([code], { type: 'text/plain' });
      formData.append('contract', blob, 'contract.sol');

      const response = await fetch('http://localhost:8080/api/audit', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error('Analysis failed: ' + (await response.text()));
      }
      
      const results = await response.json();
      router.push(`/results?data=${encodeURIComponent(JSON.stringify(results))}`);
    } catch (err) {
      console.error('Analysis failed:', err);
      setError(err instanceof Error ? err.message : 'Analysis failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <div className="container mx-auto p-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          <div className="flex justify-between items-center">
            <h1 className="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-purple-400">
              Smart Contract Editor
            </h1>
            <div className="flex items-center gap-4">
              {error && (
                <p className="text-red-400 text-sm">
                  {error}
                </p>
              )}
              <button
                onClick={handleAnalyze}
                disabled={loading}
                className={`px-6 py-2 rounded-lg transition-colors flex items-center gap-2 ${
                  loading 
                    ? 'bg-gray-600 cursor-not-allowed' 
                    : 'bg-indigo-600 hover:bg-indigo-700'
                }`}
              >
                {loading ? (
                  <>
                    <svg className="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Analyzing...
                  </>
                ) : (
                  'Analyze Contract'
                )}
              </button>
            </div>
          </div>

          <div className="h-[800px] rounded-xl overflow-hidden border border-gray-700">
            <Editor
              defaultLanguage="sol"
              theme="vs-dark"
              value={code}
              onChange={handleEditorChange}
              options={{
                minimap: { enabled: true },
                fontSize: 14,
                lineNumbers: 'on',
                roundedSelection: true,
                scrollBeyondLastLine: false,
                automaticLayout: true,
                wordWrap: 'on',
                suggestOnTriggerCharacters: true,
              }}
            />
          </div>
        </motion.div>
      </div>
    </div>
  );
}
