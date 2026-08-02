# ==============================
# File: llm_agents/agent_coordinator.py
# ==============================
import os
from typing import Dict
from pathlib import Path
# Import the new function
from rag.doc_db import get_vuln_retriever_from_json
from utils.token_tracker import performance_tracker, token_tracker

# CHANGED: import SkepticAgent
from .agents.analyzer import AnalyzerAgent
from .agents.exploiter import ExploiterAgent
from .agents.generator import GeneratorAgent
from .agents.skeptic import SkepticAgent
from .agents.runner import ExploitRunner
from .agents.project_context_llm import ProjectContextLLMAgent
from .config import ModelConfig

from utils.print_utils import print_step, print_success, print_warning
from utils.token_tracker import performance_tracker

class AgentCoordinator:
    def __init__(self, model_config=None, use_rag=True):
        """
        Initialize the agent coordinator with configurable models.

        Args:
            model_config: Optional ModelConfig instance. If None, default config will be used.
            use_rag: Boolean to enable/disable Retrieval Augmented Generation for analysis.
        """
        self.model_config = model_config or ModelConfig()
        self.use_rag = use_rag

        # Initialize retriever only if RAG is enabled
        # Initialize retriever only if RAG is enabled
        if self.use_rag:
            try:
                PROJECT_ROOT = Path(__file__).resolve().parent.parent

                self.vuln_retriever = get_vuln_retriever_from_json(
                    json_path=str(PROJECT_ROOT / "known_vulnerabilities" / "contract_vulns.json"),
                    base_dataset_dir=str(PROJECT_ROOT / "known_vulnerabilities"),
                    persist_directory=str(PROJECT_ROOT / "chroma_db"),
                    top_k=3,
        )       
                if self.vuln_retriever is None:
                    print_warning("RAG unavailable. Continuing without ChromaDB.")

            except Exception as e:
                print_warning(f"Failed to initialize RAG: {e}")
                self.vuln_retriever = None
        else:
            self.vuln_retriever = None

        self.project_context = ProjectContextLLMAgent(model_config=self.model_config)
        self.analyzer = AnalyzerAgent(self.vuln_retriever, model_config=self.model_config)
        self.skeptic = SkepticAgent(model_config=self.model_config)
        self.exploiter = ExploiterAgent(model_config=self.model_config)
        self.generator = GeneratorAgent(model_config=self.model_config)
        self.runner = ExploitRunner(model_config=self.model_config)

    def analyze_contract(self, contract_info: Dict, auto_run_config: Dict = None) -> Dict:
        from rich.console import Console
        console = Console()

        def log_findings(stage: str, findings: list) -> None:
            console.print(f"[bold]{stage}: {len(findings)} finding(s)[/bold]")
            for finding in findings:
                confidence = finding.get("skeptic_confidence", finding.get("confidence_score", 0))
                console.print(
                    f"  - {finding.get('vulnerability_type')} | confidence={confidence} | "
                    f"functions={finding.get('affected_functions', [])}"
                )

        # Set default auto-run config if none provided
        if auto_run_config is None:
            auto_run_config = {"auto_run": True, "max_retries": 3}

        # Configure runner's max retries
        self.runner.max_retries = auto_run_config.get("max_retries", 3)

        # 1. ProjectContextLLMAgent => inter-contract relationships
        if "contracts_dir" in contract_info and contract_info["contracts_dir"]:
            performance_tracker.start_stage("project_context_agent")
            console.print("[bold blue]🔍 ProjectContextLLMAgent: Analyzing contract relationships...[/bold blue]")
            project_context_results = self.project_context.analyze_project(
                contract_info["contracts_dir"],
                contract_info.get("call_graph")
            )
            
            # Display the project context insights
            insights = project_context_results.get("insights", [])
            dependencies = project_context_results.get("dependencies", [])
            if insights or dependencies:
                console.print(f"[bold green]✓ ProjectContextLLMAgent: Found {len(insights)} insights and {len(dependencies)} dependencies[/bold green]")
                
                if insights:
                    console.print("[bold]Key insights:[/bold]")
                    for i, insight in enumerate(insights[:3]):  # Show top 3 insights
                        console.print(f"  - {insight}")
                    if len(insights) > 3:
                        console.print(f"  - ...and {len(insights) - 3} more insights")
                
                if dependencies:
                    console.print("[bold]Important dependencies:[/bold]")
                    for i, dep in enumerate(dependencies[:3]):  # Show top 3 dependencies
                        console.print(f"  - {dep}")
                    if len(dependencies) > 3:
                        console.print(f"  - ...and {len(dependencies) - 3} more dependencies")
            else:
                console.print("[bold yellow]ProjectContextLLMAgent: No significant insights found[/bold yellow]")
                
            # Add project context to contract_info for the analyzer
            contract_info["project_context"] = project_context_results

        # 2. Analyzer => all vulnerabilities
        performance_tracker.start_stage("analyzer_agent")
        console.print("\n[bold blue]🔍 AnalyzerAgent: Starting vulnerability detection...[/bold blue]")
        vuln_results = self.analyzer.analyze(contract_info)
        vulnerabilities = vuln_results.get("vulnerabilities", [])
        if not vulnerabilities:
            console.print("[bold yellow]AnalyzerAgent: No vulnerabilities found[/bold yellow]")
            return {"status": "no_vulnerability_found"}

        console.print(f"[bold green]✓ AnalyzerAgent: Found {len(vulnerabilities)} potential vulnerabilities[/bold green]")
        log_findings("Analyzer findings", vulnerabilities)
        for i, v in enumerate(vulnerabilities):
            console.print(f"  - {v.get('vulnerability_type')} (confidence: {v.get('confidence_score', 0):.2f})")

        # 2. Skeptic => re-check validity
        performance_tracker.start_stage("skeptic_agent")
        console.print("\n[bold blue]🧐 SkepticAgent: Re-checking vulnerability validity...[/bold blue]")
        rechecked_vulns = self.skeptic.audit_vulnerabilities(
            contract_info["source_code"], vulnerabilities, contract_info.get("function_details", [])
        )

        log_findings("Skeptic findings", rechecked_vulns)

        console.print("[bold green]✓ SkepticAgent: Completed verification[/bold green]")
        for i, v in enumerate(rechecked_vulns):
            old_score = v.get('confidence_score', 0)
            new_score = v.get('skeptic_confidence', 0)
            change = "↑" if new_score > old_score else "↓" if new_score < old_score else "→"
            console.print(f"  - {v.get('vulnerability_type')}: {old_score:.2f} {change} {new_score:.2f}")

        # 3. Generate PoCs for high-confidence vulnerabilities
        generated_pocs = []
        high_conf_vulns = [
    v for v in rechecked_vulns
    if float(v.get("skeptic_confidence", 0)) >= 0.6
]

        # Process high confidence vulnerabilities
        if high_conf_vulns:
            performance_tracker.start_stage("exploiter_agent")
            console.print(f"\n[bold blue]💡 ExploiterAgent: Generating exploit plans for {len(high_conf_vulns)} vulnerabilities...[/bold blue]")

            for i, vul in enumerate(high_conf_vulns):
                console.print(f"  Working on {vul.get('vulnerability_type')} (#{i+1}/{len(high_conf_vulns)})...")
                plan_data = self.exploiter.generate_exploit_plan(vul)
                
                # Store the exploit plan for each vulnerability
                poc_info = {
                    "vulnerability": vul,
                    "exploit_plan": plan_data.get("exploit_plan"),
                }
                
                # Skip PoC generation if configured to do so
                if self.model_config.skip_poc_generation:
                    console.print(f"[dim]Skipping PoC generation as requested.[/dim]")
                    generated_pocs.append(poc_info)
                    console.print(f"[bold green]✓ Generated exploit plan for {vul.get('vulnerability_type')}[/bold green]")
                    continue
                
                # Otherwise continue with PoC generation
                performance_tracker.start_stage("generator_agent")
                console.print(f"\n[bold blue]🔧 GeneratorAgent: Creating PoC for {vul.get('vulnerability_type')}...[/bold blue]")

                # First generate the BaseTestWithBalanceLog.sol file if it doesn't exist
                if not os.path.exists("exploit/test/basetest.sol"):
                    base_file = self.generator.generate_basetest_file()
                    console.print(f"[dim]Created base file: {base_file}[/dim]")

                # Generate the PoC for this vulnerability
                # Preserve target metadata so the generator imports the analyzed source by name.
                plan_data["target_contract"] = contract_info.get("target_contract", {})
                poc_data = self.generator.generate(plan_data)

                # Run and fix the exploit if auto-run is enabled
                if auto_run_config.get("auto_run", True):
                    performance_tracker.start_stage("exploit_runner")
                    console.print(f"\n[bold blue]🔍 ExploitRunner: Testing and fixing PoC...[/bold blue]")
                    run_result = self.runner.run_and_fix_exploit(poc_data)

                    if run_result.get("success"):
                        console.print(f"[bold green]✓ Test executed successfully![/bold green]")
                    else:
                        if run_result.get("retries") > 0:
                            console.print(f"[bold yellow]⚠ Test failed after {run_result.get('retries')} fix attempts[/bold yellow]")
                            console.print(f"[dim]Error: {run_result.get('error', 'Unknown error')}[/dim]")
                        else:
                            console.print(f"[bold red]✗ Test failed and could not be fixed[/bold red]")
                            console.print(f"[dim]Error: {run_result.get('error', 'Unknown error')}[/dim]")

                    # Add execution results to the PoC data
                    poc_data["execution_results"] = {
                        "success": run_result.get("success", False),
                        "retries": run_result.get("retries", 0),
                        "error": run_result.get("error", ""),
                        "output": run_result.get("output", "")[:500]  # Truncate long outputs
                    }
                else:
                    console.print(f"[dim]Auto-run disabled. Test generated but not executed.[/dim]")

                # Add PoC data to the result
                poc_info["poc_data"] = poc_data
                generated_pocs.append(poc_info)
                console.print(f"[bold green]✓ Generated demonstration for {vul.get('vulnerability_type')}[/bold green]")

        # End the last stage
        performance_tracker.end_stage()
        log_findings("Merged/final findings", rechecked_vulns)
        console.print("\n[bold green]✓ Agent workflow completed[/bold green]")
        
        # Avoid printing token stats here - we'll do it in main.py as part of the comprehensive performance summary
        
        return {
            "rechecked_vulnerabilities": rechecked_vulns,
            "generated_pocs": generated_pocs,
            "token_usage": token_tracker.get_usage_summary() if 'token_tracker' in locals() else None
        }
