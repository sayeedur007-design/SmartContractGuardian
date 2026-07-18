import React from "react";

const AnalysisOptions = ({
  options,
  onChange,
  onStartAnalysis,
  isReady,
  isAnalyzing,
}) => {
  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    onChange({
      [name]: type === "checkbox" ? checked : value,
    });
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow-md">
      <h2 className="text-xl font-semibold mb-4">Analysis Options</h2>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Context Model
          </label>
          <select
            name="context_model"
            value={options.context_model}
            onChange={handleChange}
            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
            disabled={isAnalyzing}
          >
            <option value="o3-mini">OpenAI O3 Mini</option>
            <option value="o1-mini">OpenAI O1 Mini</option>
            <option value="gpt-4o">GPT-4o</option>
            <option value="claude-3-5-haiku-latest">Claude 3.5 Haiku</option>
            <option value="claude-3-7-sonnet-latest">Claude 3.7 Sonnet</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Analyzer Model
          </label>
          <select
            name="analyzer_model"
            value={options.analyzer_model}
            onChange={handleChange}
            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
            disabled={isAnalyzing}
          >
            <option value="o3-mini">OpenAI O3 Mini</option>
            <option value="o1-mini">OpenAI O1 Mini</option>
            <option value="gpt-4o">GPT-4o</option>
            <option value="claude-3-5-haiku-latest">Claude 3.5 Haiku</option>
            <option value="claude-3-7-sonnet-latest">Claude 3.7 Sonnet</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Skeptic Model
          </label>
          <select
            name="skeptic_model"
            value={options.skeptic_model}
            onChange={handleChange}
            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
            disabled={isAnalyzing}
          >
            <option value="o3-mini">OpenAI O3 Mini</option>
            <option value="o1-mini">OpenAI O1 Mini</option>
            <option value="gpt-4o">GPT-4o</option>
            <option value="claude-3-5-haiku-latest">Claude 3.5 Haiku</option>
            <option value="claude-3-7-sonnet-latest">Claude 3.7 Sonnet</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Exploiter Model
          </label>
          <select
            name="exploiter_model"
            value={options.exploiter_model}
            onChange={handleChange}
            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
            disabled={isAnalyzing}
          >
            <option value="o3-mini">OpenAI O3 Mini</option>
            <option value="o1-mini">OpenAI O1 Mini</option>
            <option value="gpt-4o">GPT-4o</option>
            <option value="claude-3-5-haiku-latest">Claude 3.5 Haiku</option>
            <option value="claude-3-7-sonnet-latest">Claude 3.7 Sonnet</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Generator Model
          </label>
          <select
            name="generator_model"
            value={options.generator_model}
            onChange={handleChange}
            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
            disabled={isAnalyzing}
          >
            <option value="o3-mini">OpenAI O3 Mini</option>
            <option value="o1-mini">OpenAI O1 Mini</option>
            <option value="gpt-4o">GPT-4o</option>
            <option value="claude-3-5-haiku-latest">Claude 3.5 Haiku</option>
            <option value="claude-3-7-sonnet-latest">Claude 3.7 Sonnet</option>
          </select>
        </div>

        <div className="flex items-center">
          <input
            id="auto_run"
            name="auto_run"
            type="checkbox"
            checked={options.auto_run}
            onChange={handleChange}
            className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            disabled={isAnalyzing}
          />
          <label
            htmlFor="auto_run"
            className="ml-2 block text-sm text-gray-700"
          >
            Auto-run generated exploits
          </label>
        </div>

        <div className="flex items-center">
          <input
            id="use_rag"
            name="use_rag"
            type="checkbox"
            checked={options.use_rag}
            onChange={handleChange}
            className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            disabled={isAnalyzing}
          />
          <label htmlFor="use_rag" className="ml-2 block text-sm text-gray-700">
            Use RAG (Retrieval Augmented Generation) for enhanced analysis
          </label>
        </div>
        
        <div className="flex items-center">
          <input
            id="skip_poc_generation"
            name="skip_poc_generation"
            type="checkbox"
            checked={options.skip_poc_generation}
            onChange={handleChange}
            className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            disabled={isAnalyzing}
          />
          <label htmlFor="skip_poc_generation" className="ml-2 block text-sm text-gray-700">
            Skip PoC generation (stop at exploit plans)
          </label>
        </div>
        
        <div className="flex items-center">
          <input
            id="export_markdown"
            name="export_markdown"
            type="checkbox"
            checked={options.export_markdown}
            onChange={handleChange}
            className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            disabled={isAnalyzing}
          />
          <label htmlFor="export_markdown" className="ml-2 block text-sm text-gray-700">
            Export report as Markdown
          </label>
        </div>

        {options.auto_run && !options.skip_poc_generation && (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Max Fix Retries
            </label>
            <input
              type="number"
              name="max_retries"
              value={options.max_retries}
              onChange={handleChange}
              className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
              min="1"
              max="5"
              disabled={isAnalyzing}
            />
          </div>
        )}

        <button
          type="button"
          className="w-full py-2.5 px-5 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
          onClick={onStartAnalysis}
          disabled={!isReady || isAnalyzing}
        >
          {isAnalyzing ? "Analysis in Progress..." : "Start Analysis"}
        </button>
      </div>
    </div>
  );
};

export default AnalysisOptions;
