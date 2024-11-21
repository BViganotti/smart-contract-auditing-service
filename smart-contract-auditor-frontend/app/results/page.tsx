'use client';

import { useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import Results from '../components/Results';
import { motion } from 'framer-motion';

interface AnalysisHistory {
  timestamp: number;
  contractName: string;
  results: any;
}

export default function ResultsPage() {
  const searchParams = useSearchParams();
  const [results, setResults] = useState<any>(null);
  const [history, setHistory] = useState<AnalysisHistory[]>([]);

  useEffect(() => {
    // Get results from URL
    const data = searchParams.get('data');
    if (data) {
      const parsedData = JSON.parse(decodeURIComponent(data));
      setResults(parsedData);

      // Update history
      const newHistory: AnalysisHistory = {
        timestamp: Date.now(),
        contractName: 'Contract ' + (history.length + 1),
        results: parsedData,
      };

      const updatedHistory = [newHistory, ...history].slice(0, 10); // Keep last 10 analyses
      setHistory(updatedHistory);
      localStorage.setItem('analysisHistory', JSON.stringify(updatedHistory));
    }
  }, [searchParams]);

  useEffect(() => {
    // Load history from localStorage
    const savedHistory = localStorage.getItem('analysisHistory');
    if (savedHistory) {
      setHistory(JSON.parse(savedHistory));
    }
  }, []);

  const handleHistoryItemClick = (item: AnalysisHistory) => {
    setResults(item.results);
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <div className="container mx-auto p-6">
        <div className="flex gap-6">
          {/* History Sidebar */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            className="w-64 shrink-0"
          >
            <div className="bg-gray-800 rounded-xl p-4">
              <h2 className="text-xl font-semibold text-gray-200 mb-4">Analysis History</h2>
              <div className="space-y-2">
                {history.map((item, index) => (
                  <button
                    key={item.timestamp}
                    onClick={() => handleHistoryItemClick(item)}
                    className="w-full text-left p-3 rounded-lg bg-gray-700 hover:bg-gray-600 transition-colors"
                  >
                    <div className="text-sm font-medium text-gray-200">{item.contractName}</div>
                    <div className="text-xs text-gray-400">
                      {new Date(item.timestamp).toLocaleString()}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </motion.div>

          {/* Results */}
          <div className="flex-1">
            {results ? (
              <Results data={results} />
            ) : (
              <div className="flex items-center justify-center h-64">
                <p className="text-gray-400">No results to display</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
