import React from 'react';
import { motion } from 'framer-motion';

interface Warning {
  category: string;
  message: string;
  line_number: number;
  code_snippet: string;
}

interface Vulnerability {
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  location: {
    start: number;
    end: number;
  };
  code_snippet?: string;
  recommendation?: string;
  category: string;
}

interface GasUsage {
  estimated_deployment_cost: number;
  estimated_function_costs: Array<[string, number]>;
}

interface AnalysisSummary {
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  medium_vulnerabilities: number;
  low_vulnerabilities: number;
  total_warnings: number;
  gas_efficiency_score: number;
  code_quality_score: number;
}

interface ResultsProps {
  data: {
    warnings: Warning[];
    vulnerabilities: Vulnerability[];
    gas_usage: GasUsage;
    complexity_score: number;
    function_complexities: Record<string, number>;
    summary: AnalysisSummary;
    analysis_time: {
      secs: number;
      nanos: number;
    };
    error?: string;
  };
}

export default function Results({ data }: ResultsProps) {
  return (
    <div className="w-full max-w-7xl mx-auto p-6">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="space-y-6"
      >
        {data.error ? (
          <div className="gradient-border">
            <div className="p-4">
              <p className="text-red-400">Error: {data.error}</p>
            </div>
          </div>
        ) : (
          <>
            <SummarySection summary={data.summary} />
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <VulnerabilitiesSection vulnerabilities={data.vulnerabilities} />
              <div className="space-y-6">
                <WarningsSection warnings={data.warnings} />
                <MetricsSection 
                  gasUsage={data.gas_usage}
                  complexityScore={data.complexity_score}
                  functionComplexities={data.function_complexities}
                />
              </div>
            </div>
          </>
        )}
        
        <div className="text-sm text-gray-400 text-right">
          Analysis completed in {(data.analysis_time.secs * 1000 + data.analysis_time.nanos / 1000000).toFixed(2)}ms
        </div>
      </motion.div>
    </div>
  );
}

function SummarySection({ summary }: { summary: AnalysisSummary }) {
  return (
    <div className="glass-card p-6 rounded-xl">
      <h2 className="text-2xl font-bold mb-6 bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-purple-400">
        Smart Contract Analysis Summary
      </h2>
      <div className="stats-grid">
        <StatCard
          title="Total Issues"
          value={summary.total_vulnerabilities + summary.total_warnings}
          icon="🔍"
          trend={0}
        />
        <StatCard
          title="Critical Issues"
          value={summary.critical_vulnerabilities}
          icon="⚠️"
          trend={summary.critical_vulnerabilities > 0 ? 1 : -1}
        />
        <StatCard
          title="Code Quality"
          value={summary.code_quality_score}
          icon="✨"
          trend={summary.code_quality_score > 80 ? -1 : 1}
          suffix="%"
        />
        <StatCard
          title="Gas Efficiency"
          value={summary.gas_efficiency_score}
          icon="⚡"
          trend={summary.gas_efficiency_score > 80 ? -1 : 1}
          suffix="%"
        />
      </div>
    </div>
  );
}

function StatCard({ 
  title, 
  value, 
  icon, 
  trend, 
  suffix = '' 
}: { 
  title: string; 
  value: number; 
  icon: string;
  trend: number;
  suffix?: string;
}) {
  return (
    <div className="gradient-border">
      <div className="p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-lg">{icon}</span>
          <span className={`text-sm ${
            trend > 0 ? 'text-red-400' : 
            trend < 0 ? 'text-green-400' : 
            'text-gray-400'
          }`}>
            {trend > 0 ? '↑' : trend < 0 ? '↓' : '−'}
          </span>
        </div>
        <h3 className="text-gray-400 text-sm mb-1">{title}</h3>
        <p className="text-2xl font-bold">{value}{suffix}</p>
      </div>
    </div>
  );
}

function VulnerabilitiesSection({ vulnerabilities }: { vulnerabilities: Vulnerability[] }) {
  return (
    <div className="glass-card p-6 rounded-xl">
      <h3 className="text-xl font-bold mb-4 bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-purple-400">
        Security Vulnerabilities
      </h3>
      <div className="space-y-4">
        {vulnerabilities.map((vuln, index) => (
          <motion.div
            key={index}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.1 }}
          >
            <div className="gradient-border">
              <div className="p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-1 rounded text-sm font-medium ${
                      vuln.severity === 'Critical' ? 'bg-red-500/20 text-red-400' :
                      vuln.severity === 'High' ? 'bg-orange-500/20 text-orange-400' :
                      vuln.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-blue-500/20 text-blue-400'
                    }`}>
                      {vuln.severity}
                    </span>
                    <span className="text-sm text-gray-400">{vuln.category}</span>
                  </div>
                  <span className="text-sm text-gray-400">Line {vuln.location.start}</span>
                </div>
                
                <p className="text-gray-300 mb-3">{vuln.description}</p>
                
                {vuln.code_snippet && (
                  <div className="mb-3 p-3 bg-gray-900/50 rounded-lg">
                    <pre className="text-sm text-gray-300 font-mono overflow-x-auto">
                      {vuln.code_snippet}
                    </pre>
                  </div>
                )}
                
                {vuln.recommendation && (
                  <div className="border-t border-gray-700 pt-3">
                    <h4 className="text-sm font-semibold text-indigo-400 mb-2">Recommendation</h4>
                    <pre className="text-sm text-gray-300 font-mono whitespace-pre-wrap">
                      {vuln.recommendation}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}

function WarningsSection({ warnings }: { warnings: Warning[] }) {
  return (
    <div className="glass-card p-6 rounded-xl">
      <h3 className="text-xl font-bold mb-4 bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-purple-400">
        Code Warnings
      </h3>
      <div className="space-y-3">
        {warnings.map((warning, index) => (
          <motion.div
            key={index}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.1 }}
          >
            <div className="gradient-border">
              <div className="p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-yellow-400">
                    {warning.category}
                  </span>
                  <span className="text-sm text-gray-400">
                    Line {warning.line_number}
                  </span>
                </div>
                <p className="text-gray-300 mb-2">{warning.message}</p>
                {warning.code_snippet && (
                  <pre className="text-sm text-gray-400 font-mono bg-gray-900/50 p-2 rounded">
                    {warning.code_snippet}
                  </pre>
                )}
              </div>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}

function MetricsSection({ 
  gasUsage, 
  complexityScore,
  functionComplexities 
}: { 
  gasUsage: GasUsage;
  complexityScore: number;
  functionComplexities: Record<string, number>;
}) {
  return (
    <div className="glass-card p-6 rounded-xl">
      <h3 className="text-xl font-bold mb-4 bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-purple-400">
        Performance Metrics
      </h3>
      
      <div className="space-y-4">
        <div className="gradient-border">
          <div className="p-4">
            <h4 className="text-gray-400 mb-2">Gas Usage</h4>
            <div className="text-xl font-bold mb-1">
              {gasUsage.estimated_deployment_cost.toLocaleString()} gas
            </div>
            <p className="text-sm text-gray-400">Estimated deployment cost</p>
          </div>
        </div>

        <div className="gradient-border">
          <div className="p-4">
            <h4 className="text-gray-400 mb-2">Code Complexity</h4>
            <div className="text-xl font-bold mb-1">
              {complexityScore}/100
            </div>
            <div className="h-2 bg-gray-700 rounded-full mt-2">
              <div 
                className="h-full rounded-full animated-gradient"
                style={{ width: `${complexityScore}%` }}
              />
            </div>
          </div>
        </div>

        <div>
          <h4 className="text-gray-400 mb-2">Function Complexity</h4>
          {Object.entries(functionComplexities).map(([func, score], index) => (
            <div key={index} className="mb-2">
              <div className="flex justify-between text-sm mb-1">
                <span className="text-gray-300">{func}</span>
                <span className="text-gray-400">{score}</span>
              </div>
              <div className="h-1 bg-gray-700 rounded-full">
                <div 
                  className="h-full rounded-full bg-gradient-to-r from-indigo-400 to-purple-400"
                  style={{ width: `${(score / 100) * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
