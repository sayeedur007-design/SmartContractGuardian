import React, { useRef, useState } from "react";
import { Download, FileCode2, FolderOpen, RotateCcw, ShieldCheck, UploadCloud } from "lucide-react";
import { generateSecureContract } from "../services/api";

const API_ORIGIN = "http://localhost:3000";
const SecureGeneratorPage = () => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [fileError, setFileError] = useState("");
  const [result, setResult] = useState(null);
  const fileInputRef = useRef(null);

  const selectFile = (file) => {
    if (!file || isGenerating) return;

    if (!file.name.toLowerCase().endsWith(".sol")) {
      setFileError("Please choose a Solidity (.sol) file.");
      return;
    }

    setSelectedFile(file);
    setFileError("");
  };

  const handleFileChange = (event) => {
    selectFile(event.target.files?.[0]);
    event.target.value = "";
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setIsDragging(false);
    selectFile(event.dataTransfer.files?.[0]);
  };

  const handleGenerate = async () => {
    if (!selectedFile || isGenerating) return;

    setIsGenerating(true);
    setFileError("");
    try {
      const formData = new FormData();
      formData.append("file", selectedFile);
      const response = await generateSecureContract(formData);
      if (!response.data?.generated_code || !response.data?.download_url) {
        throw new Error("The server did not return a generated secure contract.");
      }
      setResult(response.data);
    } catch (error) {
      setFileError(error.response?.data?.error || error.message || "Unable to generate a secure contract.");
    } finally {
      setIsGenerating(false);
    }
  };

  const generateAnother = () => {
    setResult(null);
    setSelectedFile(null);
    setFileError("");
    setIsDragging(false);
  };

  if (result) {
    return (
      <section className="placeholder-page">
        <div className="placeholder-page-heading">
          <h1>🛠️ Secure Contract Generator</h1>
          <p>Generate secure versions of vulnerable Solidity smart contracts using AI.</p>
        </div>
        <article className="placeholder-card">
          <div className="upload-section-heading">
            <div className="upload-tab"><ShieldCheck size={25} /> Security Summary</div>
            <p>{result.security_summary}</p>
          </div>
          <div className="feature-grid">
            <article className="feature-card"><FileCode2 size={28} className="feature-icon blue" /><div><h3>Vulnerabilities Detected</h3><p>{result.vulnerabilities_detected}</p></div></article>
            <article className="feature-card"><ShieldCheck size={28} className="feature-icon cyan" /><div><h3>Validation Status</h3><p>{result.validation_status}</p></div></article>
            <article className="feature-card"><ShieldCheck size={28} className="feature-icon emerald" /><div><h3>Compile Status</h3><p>{result.compile_status}</p></div></article>
          </div>
          <div className="paste-code-actions">
            <button type="button" disabled={!result.generated_code || !result.download_url} onClick={() => window.location.assign(`${API_ORIGIN}${result.download_url}`)}><Download size={18} /> Download Secure Contract</button>
            <button type="button" onClick={generateAnother}><RotateCcw size={18} /> Generate Another</button>
          </div>
        </article>
      </section>
    );
  }

  return (
    <section className="placeholder-page">
      <div className="placeholder-page-heading">
        <h1>🛠️ Secure Contract Generator</h1>
        <p>Generate secure versions of vulnerable Solidity smart contracts using AI.</p>
      </div>
      <article className="placeholder-card">
        <div className="upload-section-heading">
          <div className="upload-tab"><UploadCloud size={25} /> Upload Solidity Contract</div>
          <p>Upload a Solidity contract to prepare it for secure contract generation.</p>
        </div>
        <div
          className={`upload-dropzone ${isDragging ? "is-dragging" : ""}`}
          onClick={() => !isGenerating && fileInputRef.current?.click()}
          onDragOver={(event) => { event.preventDefault(); if (!isGenerating) setIsDragging(true); }}
          onDragLeave={(event) => { if (!event.currentTarget.contains(event.relatedTarget)) setIsDragging(false); }}
          onDrop={handleDrop}
          role="button"
          tabIndex={isGenerating ? -1 : 0}
          aria-disabled={isGenerating}
          onKeyDown={(event) => {
            if (!isGenerating && (event.key === "Enter" || event.key === " ")) {
              event.preventDefault();
              fileInputRef.current?.click();
            }
          }}
        >
          <input ref={fileInputRef} className="hidden" type="file" accept=".sol" disabled={isGenerating} onChange={handleFileChange} />
          <FileCode2 className="upload-icon" aria-hidden="true" />
          <p className="upload-title">{isGenerating ? "Generating secure contract..." : "Drag & Drop your .sol file here"}</p>
          <p className="upload-action">or</p>
          <button className="browse-files-button" type="button" disabled={isGenerating} onClick={(event) => { event.stopPropagation(); fileInputRef.current?.click(); }}>
            <FolderOpen size={21} /> Choose .sol File
          </button>
          {selectedFile && <p className="upload-file">Selected: {selectedFile.name}</p>}
        </div>
        {fileError && <p className="upload-error" role="alert">{fileError}</p>}
        <button className="start-analysis-button" type="button" disabled={!selectedFile || isGenerating} onClick={handleGenerate}>
          <ShieldCheck size={27} />
          <span>{isGenerating ? "Generating Secure Contract..." : "Generate Secure Contract"}</span>
        </button>
      </article>
    </section>
  );
};

export default SecureGeneratorPage;
