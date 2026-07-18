import React, { useState, useEffect, useRef } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Header from "./components/Header";
import ContractInput from "./components/ContractInput";
import AnalysisOptions from "./components/AnalysisOptions";
import AgentVisualizer from "./components/AgentVisualizer";
import VulnerabilitiesPanel from "./components/VulnerabilitiesPanel";
import ExploitsPanel from "./components/ExploitsPanel";
import ProjectContextPanel from "./components/ProjectContextPanel";
import PerformanceMetricsPanel from "./components/PerformanceMetricsPanel";
import { io } from "socket.io-client";
import {
  fetchContractStatus,
  fetchContractResults,
  startAnalysis,
} from "./services/api";
import "./App.css";

// Initialize socket.io client - make sure port matches your backend
const socket = io("http://localhost:3000");

function App() {
  const [currentJob, setCurrentJob] = useState(null);
  const [jobStatus, setJobStatus] = useState("idle");
  const [analysisResults, setAnalysisResults] = useState(null);
  const [activeAgent, setActiveAgent] = useState(null);
  const [completedAgents, setCompletedAgents] = useState([]);
  const [agentDetails, setAgentDetails] = useState({});
  const [ragDetails, setRagDetails] = useState([]);
  const [projectContextData, setProjectContextData] = useState({});
  const [performanceMetrics, setPerformanceMetrics] = useState(null);
  const [analysisOptions, setAnalysisOptions] = useState({
    analyzer_model: "o3-mini",
    skeptic_model: "o3-mini",
    exploiter_model: "o3-mini",
    generator_model: "o3-mini",
    auto_run: true,
    max_retries: 3,
    use_rag: true,
    skip_poc_generation: false,
    export_markdown: false,
  });

  // Keep a reference to currentJob that won't cause effect hook to re-run
  const currentJobRef = useRef(null);

  useEffect(() => {
    currentJobRef.current = currentJob;
  }, [currentJob]);

  // Connect to Socket.io for real-time updates
  useEffect(() => {
    console.log("Setting up socket listeners");

    // Set up socket event listeners
    const onConnect = () => {
      console.log("Connected to server");
    };

    const onAnalysisStarted = (data) => {
      console.log("Analysis started event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        setJobStatus("analyzing");
      }
    };

    const onAgentActive = (data) => {
      console.log("Agent active event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        setActiveAgent(data.agent);
      }
    };

    const onAgentComplete = (data) => {
      console.log("Agent complete event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        const agent = data.agent;

        // Add to completed agents list
        setCompletedAgents((prev) => {
          if (!prev.includes(agent)) {
            return [...prev, agent];
          }
          return prev;
        });

        // Save the result if provided
        if (data.result) {
          setAgentDetails((prev) => ({
            ...prev,
            [agent]: {
              ...prev[agent],
              result: data.result,
              timestamp: new Date().toISOString(),
            },
          }));
        }

        // If this agent was active, clear it
        setActiveAgent((prev) => (prev === agent ? null : prev));
      }
    };

    const onAnalysisComplete = async (data) => {
      console.log("Analysis complete event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        setJobStatus("completed");
        setActiveAgent(null);

        // Fetch full results
        try {
          const results = await fetchContractResults(data.job_id);
          setAnalysisResults(results.data.results);
          
          // Set performance metrics if available
          if (data.performance_metrics) {
            setPerformanceMetrics(data.performance_metrics);
          } else if (results.data.performance_metrics) {
            setPerformanceMetrics(results.data.performance_metrics);
          }
        } catch (error) {
          console.error("Error fetching results:", error);
        }
      }
    };

    const onAnalysisError = (data) => {
      console.log("Analysis error event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        setJobStatus("error");
        setActiveAgent(null);
      }
    };

    const onContractFetched = (data) => {
      console.log("Contract fetched event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        setJobStatus("fetched");
      }
    };

    const onAgentStatus = (data) => {
      console.log("Agent status event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        setAgentDetails((prev) => ({
          ...prev,
          [data.agent]: {
            status: data.status,
            detail: data.detail,
            timestamp: new Date().toISOString(),
          },
        }));
      }
    };

    const onRagDetails = (data) => {
      console.log("RAG details event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        setRagDetails(data.details || []);
      }
    };
    
    const onProjectContextInsights = (data) => {
      console.log("Project context insights event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        setProjectContextData(data.details || {});
      }
    };

    const onContractFetchError = (data) => {
      console.log("Contract fetch error event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        setJobStatus("error");
      }
    };

    socket.on("connect", onConnect);
    socket.on("analysis_started", onAnalysisStarted);
    socket.on("agent_active", onAgentActive);
    socket.on("agent_complete", onAgentComplete);
    socket.on("agent_status", onAgentStatus);
    socket.on("rag_details", onRagDetails);
    socket.on("project_context_insights", onProjectContextInsights);
    socket.on("analysis_complete", onAnalysisComplete);
    socket.on("analysis_error", onAnalysisError);
    socket.on("contract_fetched", onContractFetched);
    socket.on("contract_fetch_error", onContractFetchError);

    // Clean up on unmount
    return () => {
      console.log("Cleaning up socket listeners");
      socket.off("connect", onConnect);
      socket.off("analysis_started", onAnalysisStarted);
      socket.off("agent_active", onAgentActive);
      socket.off("agent_complete", onAgentComplete);
      socket.off("agent_status", onAgentStatus);
      socket.off("rag_details", onRagDetails);
      socket.off("project_context_insights", onProjectContextInsights);
      socket.off("analysis_complete", onAnalysisComplete);
      socket.off("analysis_error", onAnalysisError);
      socket.off("contract_fetched", onContractFetched);
      socket.off("contract_fetch_error", onContractFetchError);
    };
  }, []); // Empty dependency array to set up only once

  // Poll job status if not completed or error
  useEffect(() => {
    let interval;
    if (
      currentJob &&
      ["uploaded", "fetched", "analyzing"].includes(jobStatus)
    ) {
      interval = setInterval(async () => {
        try {
          const response = await fetchContractStatus(currentJob.id);
          setJobStatus(response.data.status);

          if (response.data.status === "completed") {
            const results = await fetchContractResults(currentJob.id);
            setAnalysisResults(results.data.results);
            clearInterval(interval);
          } else if (response.data.status === "error") {
            clearInterval(interval);
          }
        } catch (error) {
          console.error("Error polling job status:", error);
        }
      }, 5000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [currentJob, jobStatus]);

  const handleContractSubmit = (jobData) => {
    setCurrentJob(jobData);
    setJobStatus(jobData.status);
    setAnalysisResults(null);
    setActiveAgent(null);
    setCompletedAgents([]); // Reset completed agents
    setAgentDetails({}); // Reset agent details
    setRagDetails([]); // Reset RAG details
    setProjectContextData({}); // Reset project context data
    setPerformanceMetrics(null); // Reset performance metrics
  };

  const handleStartAnalysis = async () => {
    if (!currentJob) return;

    try {
      await startAnalysis({
        job_id: currentJob.id,
        ...analysisOptions,
      });
      setJobStatus("analyzing");
    } catch (error) {
      console.error("Error starting analysis:", error);
    }
  };

  const handleOptionsChange = (options) => {
    setAnalysisOptions({
      ...analysisOptions,
      ...options,
    });
  };

  return (
    <Router>
      <div className="min-h-screen bg-gray-100">
        <Header />

        <main className="container mx-auto p-4 md:p-6 max-w-7xl">
          <Routes>
            <Route
              path="/"
              element={
                <>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                    <ContractInput onContractSubmit={handleContractSubmit} />
                    <AnalysisOptions
                      options={analysisOptions}
                      onChange={handleOptionsChange}
                      onStartAnalysis={handleStartAnalysis}
                      isReady={
                        currentJob &&
                        ["uploaded", "fetched"].includes(jobStatus)
                      }
                      isAnalyzing={jobStatus === "analyzing"}
                    />
                  </div>

                  {currentJob && (
                    <div className="mb-8">
                      <AgentVisualizer
                        activeAgent={activeAgent}
                        status={jobStatus}
                        completedAgents={completedAgents}
                        agentDetails={agentDetails}
                        ragDetails={ragDetails}
                      />
                    </div>
                  )}

                  {/* Show Project Context Panel as soon as data is available */}
                  {Object.keys(projectContextData).length > 0 && (
                    <div className="mb-8">
                      <ProjectContextPanel contextData={projectContextData} />
                    </div>
                  )}
                  
                  {analysisResults && (
                    <div className="grid grid-cols-1 gap-6">
                      <VulnerabilitiesPanel
                        vulnerabilities={
                          analysisResults.rechecked_vulnerabilities || []
                        }
                      />
                      <ExploitsPanel
                        exploits={analysisResults.generated_pocs || []}
                      />
                      {performanceMetrics && (
                        <PerformanceMetricsPanel metrics={performanceMetrics} />
                      )}
                    </div>
                  )}
                </>
              }
            />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
