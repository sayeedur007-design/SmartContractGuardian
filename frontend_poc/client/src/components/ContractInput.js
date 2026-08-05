import React, { useRef, useState } from "react";
import { ArrowRight, BrainCircuit, FileCode2, Network, ShieldCheck, UploadCloud } from "lucide-react";
import { uploadContract } from "../services/api";

const featureCards = [
  { icon: ShieldCheck, title: "AI-Powered Analysis", text: "Advanced vulnerability detection using AI", color: "blue" },
  { icon: Network, title: "Project Context", text: "Understand inter-contract relationships", color: "cyan" },
  { icon: BrainCircuit, title: "Exploit Generation", text: "Automated PoC generation & testing", color: "emerald" },
  { icon: FileCode2, title: "Detailed Reports", text: "Comprehensive security reports & recommendations", color: "amber" },
];

const ContractInput = ({ onContractSubmit, onStartAnalysis, isReady, isAnalyzing }) => {
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState("");
  const [fileName, setFileName] = useState("");
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef(null);

  const handleFileUpload = async (file) => {
    if (!file?.name?.toLowerCase().endsWith(".sol")) {
      setUploadError("Please choose a Solidity (.sol) file.");
      return;
    }

    setIsUploading(true);
    setUploadError("");
    setFileName(file.name);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const response = await uploadContract(formData);
      if (!response.data?.job_id || !response.data?.status) {
        throw new Error("The server returned an invalid upload response.");
      }
      onContractSubmit({ id: response.data.job_id, name: file.name, status: response.data.status });
    } catch (error) {
      setFileName("");
      setUploadError(error.response?.data?.error || error.message || "Unable to upload the contract.");
    } finally {
      setIsUploading(false);
    }
  };

  const onDrop = (event) => {
    event.preventDefault();
    setIsDragging(false);
    handleFileUpload(event.dataTransfer.files?.[0]);
  };

  return (
    <section className="upload-glass-panel">
      <div className="upload-tab"><UploadCloud size={20} /> Upload Contract</div>
      <div
        className={`upload-dropzone ${isDragging ? "is-dragging" : ""}`}
        onClick={() => fileInputRef.current?.click()}
        onDragOver={(event) => { event.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={onDrop}
        role="button"
        tabIndex={0}
        onKeyDown={(event) => event.key === "Enter" && fileInputRef.current?.click()}
      >
        <input ref={fileInputRef} className="hidden" type="file" accept=".sol" onChange={(event) => handleFileUpload(event.target.files?.[0])} />
        <UploadCloud className="upload-icon" aria-hidden="true" />
        <p className="upload-title">{isUploading ? "Uploading contract..." : "Drag & drop your .sol file here"}</p>
        <p className="upload-action">or click to browse</p>
        <p className="upload-support"><ShieldCheck size={17} /> Supports .sol files up to 50MB</p>
        {fileName && !isUploading && <p className="upload-file">Selected: {fileName}</p>}
        {uploadError && <p className="upload-error" role="alert">{uploadError}</p>}
      </div>

      <div className="feature-grid">
        {featureCards.map(({ icon: Icon, title, text, color }) => (
          <article className="feature-card" key={title}>
            <span className={`feature-icon ${color}`}><Icon size={28} /></span>
            <div><h3>{title}</h3><p>{text}</p></div>
          </article>
        ))}
      </div>

      <button className="start-analysis-button" type="button" onClick={onStartAnalysis} disabled={!isReady || isAnalyzing || isUploading}>
        <ShieldCheck size={27} />
        <span>{isAnalyzing ? "Analysis in Progress..." : "Start Security Analysis"}</span>
        <ArrowRight size={25} className="button-arrow" />
      </button>
      <p className="upload-security"><ShieldCheck size={16} /> Your code is analyzed securely and never stored permanently</p>
    </section>
  );
};

export default ContractInput;
