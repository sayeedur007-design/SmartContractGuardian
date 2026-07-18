import React, { useState, useEffect, useRef } from 'react';
import mermaid from 'mermaid';

const ProjectContextPanel = ({ contextData }) => {
  const [activeTab, setActiveTab] = useState('insights');
  const mermaidRef = useRef(null);
  
  // Initialize mermaid
  useEffect(() => {
    mermaid.initialize({
      startOnLoad: true,
      theme: 'default',
      securityLevel: 'loose',
      flowchart: {
        htmlLabels: true,
        curve: 'basis'
      }
    });
    
    if (activeTab === 'diagram' && mermaidRef.current) {
      try {
        mermaid.contentLoaded();
      } catch (error) {
        console.error('Mermaid rendering error:', error);
      }
    }
  }, [activeTab, contextData]);
  
  // If no data, show placeholder
  if (!contextData || Object.keys(contextData).length === 0) {
    return (
      <div className="bg-white p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-semibold mb-4">Project Context Analysis</h2>
        <div className="p-4 text-center text-gray-500">
          No contract relationship data available
        </div>
      </div>
    );
  }
  
  // Extract data from context
  const { 
    insights = [], 
    dependencies = [], 
    vulnerabilities = [], 
    recommendations = [], 
    important_functions = [],
    contract_files = [],
    contract_details = [],
    mermaid_diagram = '',
    stats = {}
  } = contextData;
  
  // Function to render list items with tailwind styling
  const renderList = (items, icon) => {
    if (!items || items.length === 0) {
      return <div className="text-gray-500 italic p-3">No items found</div>;
    }
    
    return (
      <ul className="divide-y">
        {items.map((item, index) => (
          <li key={index} className="py-3 px-2 hover:bg-blue-50">
            <div className="flex items-start">
              <div className="flex-shrink-0 text-blue-500 mr-2">
                {icon || '•'}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-gray-800">{item}</p>
              </div>
            </div>
          </li>
        ))}
      </ul>
    );
  };
  
  // Get or generate mermaid diagram definition
  const generateMermaidDiagram = () => {
    // If we have an LLM-generated diagram, use it
    if (mermaid_diagram && mermaid_diagram.trim().length > 0) {
      return mermaid_diagram;
    }
    
    // Otherwise, generate a fallback diagram
    let diagram = 'graph TD;\n';
    
    // Track contracts we've seen
    const contracts = new Set();
    
    // Extract contract names directly from the contract_details
    const contractNames = [];
    if (contract_details && contract_details.length > 0) {
      contract_details.forEach(contract => {
        const name = contract.name;
        contracts.add(name);
        contractNames.push(name);
      });
    } else {
      // Fallback to extracting from file paths if no contract details
      contract_files.forEach(file => {
        const name = file.split('/').pop().replace('.sol', '');
        contracts.add(name);
        contractNames.push(name);
      });
    }
    
    // Add all contracts as nodes
    contractNames.forEach(contract => {
      diagram += `${contract}["${contract}"];\n`;
    });
    
    // Parse dependencies to add relationships
    dependencies.forEach(dep => {
      // Look for relationships mentioned in the dependency text
      const usesRegex = /(\w+)\s+(?:uses|imports|inherits from|extends|implements)\s+(\w+)/gi;
      const dependsRegex = /(\w+)\s+(?:depends on|interacts with|calls)\s+(\w+)/gi;
      
      let match;
      while ((match = usesRegex.exec(dep)) !== null) {
        const [_, from, to] = match;
        if (contractNames.includes(from) || contractNames.includes(to)) {
          diagram += `${from}-->${to};\n`;
        }
      }
      
      while ((match = dependsRegex.exec(dep)) !== null) {
        const [_, from, to] = match;
        if (contractNames.includes(from) || contractNames.includes(to)) {
          diagram += `${from}-->${to};\n`;
        }
      }
    });
    
    // If we couldn't extract any relationships, create a simpler diagram
    if (!diagram.includes('-->')) {
      diagram = 'graph TD;\n';
      // Group contracts by type (interface, library, contract)
      const interfaces = [];
      const libraries = [];
      const mainContracts = [];
      
      contractNames.forEach(name => {
        if (name.startsWith('I') && name.length > 1 && name[1].toUpperCase() === name[1]) {
          interfaces.push(name);
        } else if (name.includes('Library') || name.includes('Utils') || name.includes('Helper')) {
          libraries.push(name);
        } else {
          mainContracts.push(name);
        }
      });
      
      // Add subgraphs for different types
      if (interfaces.length > 0) {
        diagram += 'subgraph Interfaces\n';
        interfaces.forEach(name => {
          diagram += `${name}["${name}"];\n`;
        });
        diagram += 'end\n';
      }
      
      if (libraries.length > 0) {
        diagram += 'subgraph Libraries\n';
        libraries.forEach(name => {
          diagram += `${name}["${name}"];\n`;
        });
        diagram += 'end\n';
      }
      
      if (mainContracts.length > 0) {
        diagram += 'subgraph Contracts\n';
        mainContracts.forEach(name => {
          diagram += `${name}["${name}"];\n`;
        });
        diagram += 'end\n';
      }
      
      // Add some likely connections based on naming conventions
      interfaces.forEach(iface => {
        const implName = iface.substring(1); // Remove 'I' prefix
        if (mainContracts.includes(implName)) {
          diagram += `${implName}-->|implements|${iface};\n`;
        }
      });
      
      // Connect libraries to contracts that might use them
      libraries.forEach(lib => {
        mainContracts.forEach(contract => {
          diagram += `${contract}-->|may use|${lib};\n`;
        });
      });
    }
    
    return diagram;
  };
  
  // Tab configuration
  const tabs = [
    { id: 'insights', label: 'Insights', icon: '💡', count: insights.length },
    { id: 'dependencies', label: 'Dependencies', icon: '🔄', count: dependencies.length },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: '⚠️', count: vulnerabilities.length },
    { id: 'recommendations', label: 'Recommendations', icon: '✅', count: recommendations.length },
    { id: 'functions', label: 'Key Functions', icon: '🔑', count: important_functions.length },
    { id: 'diagram', label: 'Contract Diagram', icon: '📊', count: '' },
  ];
  
  return (
    <div className="bg-white p-6 rounded-lg shadow-md mb-6 border border-gray-100">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-semibold">Project Context Analysis</h2>
        <div className="text-sm text-gray-500">
          {stats.total_contracts || 0} contracts analyzed
        </div>
      </div>
      
      {/* Stats summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
        <div className="bg-blue-50 p-3 rounded-md border border-blue-100">
          <div className="text-sm text-blue-700">Contracts</div>
          <div className="text-xl font-semibold">{stats.total_contracts || 0}</div>
        </div>
        <div className="bg-green-50 p-3 rounded-md border border-green-100">
          <div className="text-sm text-green-700">Dependencies</div>
          <div className="text-xl font-semibold">{stats.total_relationships || dependencies.length || 0}</div>
        </div>
        <div className="bg-red-50 p-3 rounded-md border border-red-100">
          <div className="text-sm text-red-700">Vulnerabilities</div>
          <div className="text-xl font-semibold">{stats.total_vulnerabilities || vulnerabilities.length || 0}</div>
        </div>
        <div className="bg-purple-50 p-3 rounded-md border border-purple-100">
          <div className="text-sm text-purple-700">Recommendations</div>
          <div className="text-xl font-semibold">{stats.total_recommendations || recommendations.length || 0}</div>
        </div>
      </div>
      
      {/* Tabs */}
      <div className="border-b border-gray-200 mb-4">
        <nav className="flex -mb-px space-x-6 overflow-x-auto pb-1">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`
                py-2 px-1 border-b-2 font-medium text-sm whitespace-nowrap
                ${activeTab === tab.id 
                  ? 'border-blue-500 text-blue-600' 
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'}
              `}
            >
              <span className="mr-1">{tab.icon}</span>
              {tab.label}
              <span className="ml-1 text-xs rounded-full bg-gray-100 px-2 py-0.5">{tab.count}</span>
            </button>
          ))}
        </nav>
      </div>
      
      {/* Tab content */}
      <div className="h-64 overflow-y-auto border rounded-md">
        {activeTab === 'insights' && renderList(insights, '💡')}
        {activeTab === 'dependencies' && renderList(dependencies, '🔄')}
        {activeTab === 'vulnerabilities' && renderList(vulnerabilities, '⚠️')}
        {activeTab === 'recommendations' && renderList(recommendations, '✅')}
        {activeTab === 'functions' && renderList(important_functions, '🔑')}
        {activeTab === 'diagram' && (
          <div className="h-full p-3">
            {contract_files.length > 0 ? (
              <div className="mermaid-container h-full overflow-auto">
                <div ref={mermaidRef} className="mermaid">
                  {generateMermaidDiagram()}
                </div>
              </div>
            ) : (
              <div className="text-gray-500 italic p-3">No contracts available for diagram</div>
            )}
          </div>
        )}
      </div>
      
      {/* Contract files list */}
      {contract_files.length > 0 && (
        <div className="mt-5">
          <h3 className="text-sm font-medium text-gray-700 mb-2">Analyzed Contracts:</h3>
          <div className="flex flex-wrap gap-2">
            {contract_files.map((file, index) => (
              <span key={index} className="text-xs bg-gray-100 text-gray-800 px-2 py-1 rounded">
                {file}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default ProjectContextPanel;
