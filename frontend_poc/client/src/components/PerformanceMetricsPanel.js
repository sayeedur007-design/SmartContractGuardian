import React, { useState } from 'react';

function PerformanceMetricsPanel({ metrics }) {
  const [activeTab, setActiveTab] = useState('token');

  if (!metrics) {
    return (
      <div className="bg-white shadow-md rounded-lg p-4 mb-4">
        <h2 className="text-xl font-semibold text-gray-800 mb-4">Performance Metrics</h2>
        <p className="text-gray-600">No performance data available yet.</p>
      </div>
    );
  }

  // Format time (seconds) to a readable format with units
  const formatTime = (seconds) => {
    if (seconds < 1) {
      return `${Math.round(seconds * 1000)} ms`;
    } else if (seconds < 60) {
      return `${seconds.toFixed(2)} sec`;
    } else {
      const minutes = Math.floor(seconds / 60);
      const remainingSeconds = (seconds % 60).toFixed(1);
      return `${minutes} min ${remainingSeconds} sec`;
    }
  };

  // Format tokens to have commas for thousands
  const formatNumber = (num) => {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  };

  const renderTokenUsage = () => {
    if (!metrics.token_usage) return <p>No token data available</p>;

    return (
      <div>
        <h3 className="text-lg font-semibold text-gray-700 mb-2">Token Usage Summary</h3>
        <div className="mb-4">
          <p className="text-gray-600">
            <span className="font-medium">Total Tokens:</span> {formatNumber(metrics.token_usage.total.total_tokens)}
          </p>
          <p className="text-gray-600">
            <span className="font-medium">Prompt Tokens:</span> {formatNumber(metrics.token_usage.total.prompt_tokens)}
          </p>
          <p className="text-gray-600">
            <span className="font-medium">Completion Tokens:</span> {formatNumber(metrics.token_usage.total.completion_tokens)}
          </p>
          <p className="text-gray-600">
            <span className="font-medium">Total API Calls:</span> {metrics.token_usage.total.call_count}
          </p>
        </div>

        <h3 className="text-lg font-semibold text-gray-700 mb-2">Token Usage by Agent</h3>
        <div className="overflow-x-auto">
          <table className="min-w-full table-auto text-sm">
            <thead>
              <tr className="bg-gray-100">
                <th className="px-4 py-2 text-left">Agent</th>
                <th className="px-4 py-2 text-right">Prompt</th>
                <th className="px-4 py-2 text-right">Completion</th>
                <th className="px-4 py-2 text-right">Total</th>
                <th className="px-4 py-2 text-right">Calls</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(metrics.token_usage.by_agent).map(([agent, data]) => (
                <tr key={agent} className="border-b">
                  <td className="px-4 py-2 font-medium">{agent}</td>
                  <td className="px-4 py-2 text-right">{formatNumber(data.prompt_tokens)}</td>
                  <td className="px-4 py-2 text-right">{formatNumber(data.completion_tokens)}</td>
                  <td className="px-4 py-2 text-right">{formatNumber(data.total_tokens)}</td>
                  <td className="px-4 py-2 text-right">{data.call_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <h3 className="text-lg font-semibold text-gray-700 mt-4 mb-2">Token Usage by Model</h3>
        <div className="overflow-x-auto">
          <table className="min-w-full table-auto text-sm">
            <thead>
              <tr className="bg-gray-100">
                <th className="px-4 py-2 text-left">Model</th>
                <th className="px-4 py-2 text-right">Prompt</th>
                <th className="px-4 py-2 text-right">Completion</th>
                <th className="px-4 py-2 text-right">Total</th>
                <th className="px-4 py-2 text-right">Calls</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(metrics.token_usage.by_model).map(([model, data]) => (
                <tr key={model} className="border-b">
                  <td className="px-4 py-2 font-medium">{model}</td>
                  <td className="px-4 py-2 text-right">{formatNumber(data.prompt_tokens)}</td>
                  <td className="px-4 py-2 text-right">{formatNumber(data.completion_tokens)}</td>
                  <td className="px-4 py-2 text-right">{formatNumber(data.total_tokens)}</td>
                  <td className="px-4 py-2 text-right">{data.call_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  const renderTimeMetrics = () => {
    if (!metrics.time_metrics) return <p>No time data available</p>;

    return (
      <div>
        <h3 className="text-lg font-semibold text-gray-700 mb-2">Time Metrics</h3>
        <p className="text-gray-600 mb-4">
          <span className="font-medium">Total Analysis Time:</span> {formatTime(metrics.time_metrics.total_seconds)}
        </p>

        <h3 className="text-lg font-semibold text-gray-700 mb-2">Time by Stage</h3>
        <div className="overflow-x-auto">
          <table className="min-w-full table-auto text-sm">
            <thead>
              <tr className="bg-gray-100">
                <th className="px-4 py-2 text-left">Stage</th>
                <th className="px-4 py-2 text-right">Time</th>
                <th className="px-4 py-2 text-right">% of Total</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(metrics.time_metrics.stage_times)
                .sort((a, b) => b[1] - a[1]) // Sort by time in descending order
                .map(([stage, time]) => (
                  <tr key={stage} className="border-b">
                    <td className="px-4 py-2 font-medium">{stage}</td>
                    <td className="px-4 py-2 text-right">{formatTime(time)}</td>
                    <td className="px-4 py-2 text-right">
                      {((time / metrics.time_metrics.total_seconds) * 100).toFixed(1)}%
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  const renderCodeMetrics = () => {
    if (!metrics.code_metrics) return <p>No code metrics available</p>;

    return (
      <div>
        <h3 className="text-lg font-semibold text-gray-700 mb-2">Code Analysis</h3>
        <div className="mb-4">
          <p className="text-gray-600">
            <span className="font-medium">Lines of Code:</span> {formatNumber(metrics.code_metrics.total_lines)}
          </p>
          <p className="text-gray-600">
            <span className="font-medium">Files Analyzed:</span> {metrics.code_metrics.file_count}
          </p>
        </div>

        <h3 className="text-lg font-semibold text-gray-700 mb-2">Analyzed Files</h3>
        <div className="max-h-60 overflow-y-auto bg-gray-50 p-2 rounded text-gray-600 text-sm">
          {metrics.code_metrics.files.map((file, idx) => (
            <div key={idx} className="mb-1">
              {file}
            </div>
          ))}
        </div>
      </div>
    );
  };

  const renderDerivedMetrics = () => {
    if (!metrics.derived_metrics) return <p>No derived metrics available</p>;

    return (
      <div>
        <h3 className="text-lg font-semibold text-gray-700 mb-2">Summary Metrics</h3>
        <div className="mb-4">
          <p className="text-gray-600">
            <span className="font-medium">Tokens per Second:</span> {metrics.derived_metrics.tokens_per_second.toFixed(2)}
          </p>
          <p className="text-gray-600">
            <span className="font-medium">Tokens per Line of Code:</span> {metrics.derived_metrics.tokens_per_loc.toFixed(2)}
          </p>
        </div>

        <h3 className="text-lg font-semibold text-gray-700 mb-2">Configuration</h3>
        <div className="overflow-x-auto text-sm text-gray-600 bg-gray-50 p-3 rounded">
          {metrics.run_info.config && (
            <div>
              <div className="mb-1">
                <span className="font-medium">Analyzer Model:</span> {metrics.run_info.config.analyzer_model}
              </div>
              <div className="mb-1">
                <span className="font-medium">Skeptic Model:</span> {metrics.run_info.config.skeptic_model}
              </div>
              <div className="mb-1">
                <span className="font-medium">Exploiter Model:</span> {metrics.run_info.config.exploiter_model}
              </div>
              <div className="mb-1">
                <span className="font-medium">Generator Model:</span> {metrics.run_info.config.generator_model}
              </div>
              <div className="mb-1">
                <span className="font-medium">Context Model:</span> {metrics.run_info.config.context_model}
              </div>
              <div className="mb-1">
                <span className="font-medium">Use RAG:</span> {metrics.run_info.config.use_rag ? 'Yes' : 'No'}
              </div>
              <div className="mb-1">
                <span className="font-medium">Skip PoC:</span> {metrics.run_info.config.skip_poc ? 'Yes' : 'No'}
              </div>
              <div className="mb-1">
                <span className="font-medium">Auto Run:</span> {metrics.run_info.config.auto_run ? 'Yes' : 'No'}
              </div>
              <div className="mb-1">
                <span className="font-medium">Timestamp:</span> {metrics.run_info.timestamp}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="bg-white shadow-md rounded-lg p-4 mb-4">
      <h2 className="text-xl font-semibold text-gray-800 mb-4">Performance Metrics</h2>
      
      <div className="flex border-b mb-4">
        <button
          className={`px-4 py-2 font-medium ${activeTab === 'token' ? 'text-blue-600 border-b-2 border-blue-500' : 'text-gray-600'}`}
          onClick={() => setActiveTab('token')}
        >
          Token Usage
        </button>
        <button
          className={`px-4 py-2 font-medium ${activeTab === 'time' ? 'text-blue-600 border-b-2 border-blue-500' : 'text-gray-600'}`}
          onClick={() => setActiveTab('time')}
        >
          Time Analysis
        </button>
        <button
          className={`px-4 py-2 font-medium ${activeTab === 'code' ? 'text-blue-600 border-b-2 border-blue-500' : 'text-gray-600'}`}
          onClick={() => setActiveTab('code')}
        >
          Code Data
        </button>
        <button
          className={`px-4 py-2 font-medium ${activeTab === 'summary' ? 'text-blue-600 border-b-2 border-blue-500' : 'text-gray-600'}`}
          onClick={() => setActiveTab('summary')}
        >
          Summary
        </button>
      </div>

      <div className="p-2">
        {activeTab === 'token' && renderTokenUsage()}
        {activeTab === 'time' && renderTimeMetrics()}
        {activeTab === 'code' && renderCodeMetrics()}
        {activeTab === 'summary' && renderDerivedMetrics()}
      </div>
    </div>
  );
}

export default PerformanceMetricsPanel;
