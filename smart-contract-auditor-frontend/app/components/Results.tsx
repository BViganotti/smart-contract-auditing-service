'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

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

const getSeverityColor = (severity: string) => {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'bg-red-500';
    case 'high':
      return 'bg-orange-500';
    case 'medium':
      return 'bg-yellow-500';
    case 'low':
      return 'bg-blue-500';
    default:
      return 'bg-gray-500';
  }
};

const calculateSecurityScore = (data: ResultsProps['data']) => {
  const baseScore = 100;
  const vulnerabilityPenalties: Record<string, number> = {
    'critical': 25,
    'high': 15,
    'medium': 10,
    'low': 5,
  };

  const vulnerabilityDeductions = data.vulnerabilities.reduce((total, vuln) => {
    const severity = vuln.severity.toLowerCase();
    return total + (vulnerabilityPenalties[severity] || 0);
  }, 0);

  const complexityDeduction = Math.min(20, data.complexity_score * 2);
  const gasDeduction = Math.min(10, (data.gas_usage.estimated_deployment_cost / 1000000) * 2);

  const finalScore = Math.max(0, baseScore - vulnerabilityDeductions - complexityDeduction - gasDeduction);
  return Math.round(finalScore);
};

const getScoreGrade = (score: number) => {
  if (score >= 90) return { grade: 'A+', color: 'text-green-500' };
  if (score >= 80) return { grade: 'A', color: 'text-green-400' };
  if (score >= 70) return { grade: 'B', color: 'text-yellow-500' };
  if (score >= 60) return { grade: 'C', color: 'text-orange-500' };
  return { grade: 'D', color: 'text-red-500' };
};

export default function Results({ data }: ResultsProps) {
  const securityScore = calculateSecurityScore(data);
  const { grade, color } = getScoreGrade(securityScore);

  const chartData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      data: [
        data.vulnerabilities.filter(v => v.severity.toLowerCase() === 'critical').length,
        data.vulnerabilities.filter(v => v.severity.toLowerCase() === 'high').length,
        data.vulnerabilities.filter(v => v.severity.toLowerCase() === 'medium').length,
        data.vulnerabilities.filter(v => v.severity.toLowerCase() === 'low').length,
      ],
      backgroundColor: ['#EF4444', '#F97316', '#EAB308', '#3B82F6'],
      borderWidth: 0,
    }],
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="w-full max-w-4xl mx-auto p-6 space-y-8"
    >
      {/* Security Score Card */}
      <div className="bg-gray-800 rounded-xl p-6 shadow-lg">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold text-gray-200">Security Score</h2>
            <p className="text-gray-400 text-sm mt-1">Overall contract security rating</p>
          </div>
          <div className={`text-5xl font-bold ${color}`}>
            {grade}
          </div>
        </div>
        <div className="mt-4 h-2 bg-gray-700 rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-red-500 via-yellow-500 to-green-500"
            style={{ width: `${securityScore}%` }}
          />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Vulnerabilities Chart */}
        <div className="bg-gray-800 rounded-xl p-6 shadow-lg">
          <h2 className="text-xl font-semibold text-gray-200 mb-4">Vulnerability Distribution</h2>
          <div className="w-full h-64 flex items-center justify-center">
            <Doughnut 
              data={chartData}
              options={{
                responsive: true,
                plugins: {
                  legend: {
                    position: 'bottom',
                    labels: {
                      color: '#9CA3AF',
                    },
                  },
                },
              }}
            />
          </div>
        </div>

        {/* Metrics Card */}
        <div className="bg-gray-800 rounded-xl p-6 shadow-lg">
          <h2 className="text-xl font-semibold text-gray-200 mb-4">Contract Metrics</h2>
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-sm text-gray-400">
                <span>Gas Usage</span>
                <span>{data.gas_usage.estimated_deployment_cost.toLocaleString()} gas</span>
              </div>
              <div className="mt-1 h-2 bg-gray-700 rounded-full overflow-hidden">
                <div
                  className="h-full bg-blue-500"
                  style={{ width: `${Math.min(100, (data.gas_usage.estimated_deployment_cost / 1000000) * 100)}%` }}
                />
              </div>
            </div>
            <div>
              <div className="flex justify-between text-sm text-gray-400">
                <span>Code Complexity</span>
                <span>{data.complexity_score}/100</span>
              </div>
              <div className="mt-1 h-2 bg-gray-700 rounded-full overflow-hidden">
                <div
                  className="h-full bg-purple-500"
                  style={{ width: `${(data.complexity_score / 100) * 100}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Vulnerabilities List */}
      <div className="bg-gray-800 rounded-xl p-6 shadow-lg">
        <h2 className="text-xl font-semibold text-gray-200 mb-4">Detected Vulnerabilities</h2>
        <div className="space-y-4">
          {data.vulnerabilities.map((vulnerability, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.1 }}
              className="bg-gray-900 rounded-lg p-4"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <span className={`w-2 h-2 rounded-full ${getSeverityColor(vulnerability.severity)}`} />
                  <h3 className="text-gray-200 font-medium">{vulnerability.description}</h3>
                </div>
                <span className={`px-2 py-1 rounded text-xs ${getSeverityColor(vulnerability.severity)} bg-opacity-20 text-white`}>
                  {vulnerability.severity}
                </span>
              </div>
              <p className="mt-2 text-gray-400 text-sm">{vulnerability.description}</p>
              {vulnerability.code_snippet && (
                <div className="mt-2 bg-gray-800 rounded p-2">
                  <code className="text-xs text-gray-300 font-mono">
                    {vulnerability.code_snippet}
                  </code>
                </div>
              )}
              {vulnerability.recommendation && (
                <div className="mt-2 text-sm">
                  <span className="text-green-400">Recommendation: </span>
                  <span className="text-gray-400">{vulnerability.recommendation}</span>
                </div>
              )}
            </motion.div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}
