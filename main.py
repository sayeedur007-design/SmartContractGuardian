# ==============================
# File: main.py
# ==============================
import os
import json
import argparse
from dotenv import load_dotenv
from static_analysis.parse_contract import analyze_contract
from llm_agents.agent_coordinator import AgentCoordinator
from llm_agents.config import ModelConfig
from utils.print_utils import *
from utils.token_tracker import performance_tracker

def parse_arguments():
    """Parse command line arguments for model configuration"""
    parser = argparse.ArgumentParser(description="Smart Contract Vulnerability Analyzer")

    # Add model configuration arguments
    parser.add_argument("--analyzer-model", default="o3-mini", help="Model for analyzer agent")
    parser.add_argument("--skeptic-model", default="o3-mini", help="Model for skeptic agent")
    parser.add_argument("--exploiter-model", default="o3-mini", help="Model for exploiter agent")
    parser.add_argument("--generator-model", default="o3-mini", help="Model for generator agent")
    parser.add_argument("--context-model", default="o3-mini", help="Model for context agent")
    parser.add_argument("--all-models", help="Use this model for all agents")
    parser.add_argument("--api-base", help="Base URL for OpenAI API")

    # Add contract file option
    parser.add_argument("--contract", default="static_analysis/test_contracts/sample3.sol",
                      help="Path to contract file to analyze")
    parser.add_argument("--contract-address",
                      help="Blockchain contract address to fetch and analyze")
    parser.add_argument("--network", default="ethereum",
                      help="Blockchain network (ethereum, bsc, base, arbitrum)")
    # Removed --project-dir as it's implicitly handled by fetching or direct path
    parser.add_argument("--save-separate", action="store_true",
                      help="Save separate contract files in addition to flattened file when fetching")

    # Add auto-run options
    parser.add_argument("--no-auto-run", action="store_true",
                      help="Disable automatic execution of generated PoCs")
    parser.add_argument("--max-retries", type=int, default=3,
                      help="Maximum number of fix attempts for failed tests (default: 3)")

    # Add RAG option
    parser.add_argument("--no-rag", action="store_true",
                      help="Disable Retrieval Augmented Generation for analysis")

    # Add PoC generation and report export options
    parser.add_argument("--skip-poc", action="store_true",
                      help="Skip PoC generation and stop at exploit plans")
    parser.add_argument("--export-md", action="store_true",
                      help="Export analysis report as Markdown file")
    parser.add_argument("--export-json", help="Export results to a JSON file for automated analysis")

    return parser.parse_args()

def main():
    print_header("Smart Contract Vulnerability Analyzer")

    # Start performance tracking
    performance_tracker.reset()
    performance_tracker.start_stage("initialization")

    # Parse command line arguments
    args = parse_arguments()

    # Set run configuration for tracking
    run_config = {
        "analyzer_model": args.analyzer_model,
        "skeptic_model": args.skeptic_model,
        "exploiter_model": args.exploiter_model,
        "generator_model": args.generator_model,
        "context_model": args.context_model,
        "all_models": args.all_models,
        "use_rag": not args.no_rag,
        "skip_poc": args.skip_poc,
        "auto_run": not args.no_auto_run
    }
    performance_tracker.set_run_config(run_config)

    # Check environment
    try:
        load_dotenv()
        # Check for necessary API keys based on selected models later
        print_success("Environment loaded")
    except Exception as e:
        print_error(f"Environment setup failed: {str(e)}")
        return

    # Setup model configuration
    if args.all_models:
        model_config = ModelConfig(
            analyzer_model=args.all_models,
            skeptic_model=args.all_models,
            exploiter_model=args.all_models,
            generator_model=args.all_models,
            context_model=args.all_models,
            base_url=args.api_base,
            skip_poc_generation=args.skip_poc,
            export_markdown=args.export_md
        )
    else:
        model_config = ModelConfig(
            analyzer_model=args.analyzer_model,
            skeptic_model=args.skeptic_model,
            exploiter_model=args.exploiter_model,
            generator_model=args.generator_model,
            context_model=args.context_model,
            base_url=args.api_base,
            skip_poc_generation=args.skip_poc,
            export_markdown=args.export_md
        )

    # Display model configuration
    print_step("Configuration:")
    console.print(f"  Analyzer: [bold]{model_config.analyzer_model}[/bold]")
    console.print(f"  Skeptic: [bold]{model_config.skeptic_model}[/bold]")
    console.print(f"  Exploiter: [bold]{model_config.exploiter_model}[/bold]")
    console.print(f"  Generator: [bold]{model_config.generator_model}[/bold]")
    console.print(f"  Context: [bold]{model_config.context_model}[/bold]")
    if args.api_base:
        console.print(f"  API Base URL: [dim]{args.api_base}[/dim]")
    console.print(f"  Skip PoC Generation: [bold]{'Yes' if model_config.skip_poc_generation else 'No'}[/bold]")
    console.print(f"  Export Markdown Report: [bold]{'Yes' if model_config.export_markdown else 'No'}[/bold]")

    # Initialize variables
    filepath = args.contract
    contracts_dir = None
    contract_files_map = {}

    # Fetch contract if address is provided
    if args.contract_address:
        from utils.source_code_fetcher import fetch_and_flatten_contract

        # Create uploads directory if it doesn't exist
        uploads_dir = os.path.join(os.getcwd(), "uploads")
        os.makedirs(uploads_dir, exist_ok=True)

        # Use uploads directory for consistency
        output_file = os.path.join(uploads_dir, f"{args.contract_address}_{args.network}.sol")

        print_step(f"Fetching contract {args.contract_address} from {args.network}...")
        try:
            contract_files_map = fetch_and_flatten_contract(
                network=args.network,
                contract_address=args.contract_address,
                output_file=output_file,
                flatten=True,
                save_separate=args.save_separate
            )
            print_success(f"Contract fetched and saved to {output_file}")
            filepath = output_file # Update filepath to the fetched contract

            # Determine contracts_dir path
            if args.save_separate and contract_files_map:
                potential_dir = f"{os.path.splitext(output_file)[0]}_contracts"
                if os.path.isdir(potential_dir):
                    contracts_dir = potential_dir
                    print_step(f"Found contracts directory: {contracts_dir}")
                else:
                    print_warning(f"Expected contracts directory {potential_dir} not found.")

        except Exception as fetch_error:
            print_error(f"Failed to fetch contract: {fetch_error}")
            return
    elif os.path.isdir(args.contract):
         # Handle case where user provides a directory directly
         contracts_dir = args.contract
         # Find a main .sol file or just use the directory for Slither
         sol_files_in_dir = list(Path(contracts_dir).rglob("*.sol"))
         if sol_files_in_dir:
              # Heuristic: Find a file that isn't typically an interface/library
              main_candidates = [f for f in sol_files_in_dir if not (f.name.startswith('I') or 'interface' in f.name.lower() or 'library' in f.name.lower())]
              filepath = str(main_candidates[0]) if main_candidates else str(sol_files_in_dir[0])
              print_step(f"Analyzing project directory: {contracts_dir}")
              print_step(f"Using primary file for analysis context: {filepath}")
         else:
              print_error(f"No .sol files found in directory: {contracts_dir}")
              return
    elif not os.path.exists(filepath):
        print_error(f"Contract file not found: {filepath}")
        return

    # --- REMOVED log_code_analysis call from here ---

    # Start static analysis stage
    performance_tracker.start_stage("static_analysis")
    print_step(f"Starting static analysis on: {contracts_dir or filepath}")

    # Determine target for Slither
    analysis_target = contracts_dir if contracts_dir else filepath

    with create_progress_spinner("Running static analysis") as progress:
        task = progress.add_task("Analyzing contract structure...")
        try:
            function_details, call_graph, detector_results = analyze_contract(analysis_target)
            progress.update(task, completed=True)
            print_success(f"Static analysis complete. Found {len(function_details)} functions.")
        except Exception as slither_error:
            print_error(f"Slither analysis failed on {analysis_target}: {slither_error}")
            # Try fallback to flattened file if directory analysis failed
            if analysis_target != filepath and os.path.exists(filepath):
                 print_warning(f"Attempting static analysis fallback on: {filepath}")
                 try:
                      function_details, call_graph, detector_results = analyze_contract(filepath)
                      progress.update(task, completed=True)
                      print_success(f"Fallback static analysis complete. Found {len(function_details)} functions.")
                 except Exception as fallback_error:
                      print_error(f"Fallback static analysis also failed: {fallback_error}")
                      return # Stop if static analysis fails
            else:
                 return # Stop if static analysis fails


    # Read contract source code (primary file) for context
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source_code = f.read()
    except Exception as read_error:
        print_error(f"Failed to read contract source code from {filepath}: {read_error}")
        return


    # Prepare for LLM analysis
    contract_info = {
        "function_details": function_details,
        "call_graph": call_graph,
        "source_code": source_code, # Primary file's source code
        "detector_results": detector_results,
    }

    # Add contracts directory path if it exists
    if contracts_dir and os.path.isdir(contracts_dir):
        contract_info["contracts_dir"] = contracts_dir
        print_step(f"Added contracts directory for inter-contract analysis: {contracts_dir}")

    # Run LLM analysis
    performance_tracker.start_stage("llm_analysis")
    print_header("Running LLM Analysis")
    coordinator = AgentCoordinator(model_config=model_config, use_rag=not args.no_rag)

    # Pass auto-run configuration
    auto_run_config = {
        "auto_run": not args.no_auto_run,
        "max_retries": args.max_retries
    }

    # Display run settings
    if not args.no_auto_run:
        print_step(f"Auto-run enabled with max {args.max_retries} fix attempts")
    else:
        print_step("Auto-run disabled, PoCs will be generated but not executed")
    if not args.no_rag:
        print_step("RAG enabled for enhanced vulnerability detection")
    else:
        print_step("RAG disabled, analysis will use only current contract code")

    # Analyze the contract with all the configured agents
    results = coordinator.analyze_contract(contract_info, auto_run_config=auto_run_config)

    # Print results summary
    performance_tracker.start_stage("results_reporting")
    print_header("Analysis Results")
    rechecked = results.get("rechecked_vulnerabilities", [])

    if not rechecked:
        print_warning("No vulnerabilities found")
    else:
        print_success(f"Found {len(rechecked)} potential vulnerabilities")
        for idx, v in enumerate(rechecked, start=1):
            confidence = v.get('skeptic_confidence', 0)
            color = "red" if confidence > 0.7 else "yellow" if confidence > 0.4 else "green"
            console.print(f"\n[bold {color}]Vulnerability #{idx}: {v['vulnerability_type']}[/bold {color}] (Confidence: {confidence:.2f})")
            console.print(f"  Reasoning: {v.get('reasoning','N/A')}")
            console.print(f"  Validation: {v.get('validity_reasoning','')}")
            # Optionally print code snippets etc.

    print_header("Generated Proof of Concepts")
    pocs = results.get("generated_pocs", [])

    if not pocs:
        print_warning("No PoCs were generated")
    else:
        print_success(f"Generated {len(pocs)} PoCs for high-confidence vulnerabilities")
        for pidx, poc in enumerate(pocs, start=1):
             vuln = poc['vulnerability']
             console.print(f"\n[bold]PoC #{pidx}[/bold] - {vuln['vulnerability_type']} (Confidence: {vuln.get('skeptic_confidence', 0):.2f})")
             if "poc_data" in poc:
                  poc_data = poc["poc_data"]
                  console.print(f"  File: [green]{poc_data.get('exploit_file', 'N/A')}[/green]")
                  if "execution_results" in poc_data:
                       exec_res = poc_data["execution_results"]
                       if exec_res.get("success"):
                            console.print(f"  Execution: [bold green]SUCCESS[/bold green] ✓")
                       elif exec_res.get("success") is False:
                            console.print(f"  Execution: [bold red]FAILED[/bold red] ✗ (Retries: {exec_res.get('retries', 0)})")
                            if exec_res.get("error"):
                                console.print(f"    [dim]Error: {exec_res.get('error')[:200]}...[/dim]")
                       else:
                           console.print(f"  Execution: [bold yellow]SKIPPED[/bold yellow]")
    performance_tracker.end_stage() # End results reporting stage

    # --- MOVED log_code_analysis to here ---
    # Determine the final list of files analyzed for accurate line counting
    files_analyzed_final = []
    if contracts_dir and os.path.isdir(contracts_dir):
        try:
            # Recursively find all .sol files in the directory
            for root, _, files in os.walk(contracts_dir):
                for file in files:
                    if file.endswith('.sol'):
                        files_analyzed_final.append(os.path.join(root, file))
            if not files_analyzed_final: # Fallback if dir is empty
                if os.path.exists(filepath): # Check if primary filepath exists
                    files_analyzed_final.append(filepath)
                    print_warning(f"Contracts directory {contracts_dir} is empty. Logging LOC for primary file: {filepath}")
                else:
                    print_error(f"Contracts directory {contracts_dir} is empty and primary file {filepath} not found.")
            else:
                print_step(f"Logging analysis metrics for {len(files_analyzed_final)} files from directory: {contracts_dir}")
        except Exception as e:
            print_error(f"Error walking contracts directory {contracts_dir} for final logging: {e}. Falling back to primary file.")
            files_analyzed_final = [filepath] if os.path.exists(filepath) else []
    elif os.path.exists(filepath):
        files_analyzed_final.append(filepath)
        print_step(f"Logging analysis metrics for single file: {filepath}")
    else:
         print_error(f"Error: No valid contract path or directory found for final logging. Primary path: {filepath}")

    # Log code analysis using the determined files BEFORE getting the summary
    if files_analyzed_final:
        performance_tracker.log_code_analysis(files_analyzed_final)
        print_step(f"Final LOC count: {performance_tracker.total_lines} lines across {len(files_analyzed_final)} files.")
    else:
         print_warning("No files found to log for performance analysis.")
         performance_tracker.contract_files = []
         performance_tracker.total_lines = 0


    # Export results if requested
    performance_tracker.start_stage("export")
    if model_config.export_markdown:
        # Use primary filepath for naming consistency
        export_results_to_markdown(filepath, results)

    if args.export_json:
        export_results_to_json(filepath, results, args.export_json)
    performance_tracker.end_stage() # End export stage

    # Save and print performance metrics
    # End any final running stage if needed (export might be the last one)
    if performance_tracker.current_stage is not None:
        performance_tracker.end_stage()

    metrics_file = performance_tracker.save_to_file() # Saves the final summary
    performance_tracker.print_summary(include_detailed_breakdowns=True) # Prints the final summary

def export_results_to_markdown(contract_path, results):
    """Export analysis results to a markdown file"""
    from datetime import datetime
    import os

    # Create output filename based on the contract name
    contract_name = os.path.basename(contract_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"analysis_report_{contract_name}_{timestamp}.md"

    print_step(f"Exporting analysis report to {output_file}")

    rechecked_vulns = results.get("rechecked_vulnerabilities", [])
    pocs = results.get("generated_pocs", [])

    try:
        with open(output_file, "w", encoding='utf-8') as f:
            # Write header
            f.write(f"# Smart Contract Vulnerability Analysis Report\n\n")
            f.write(f"**Contract:** {contract_path}\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # Vulnerability summary
            f.write(f"## Vulnerability Summary\n\n")
            if not rechecked_vulns:
                f.write("No vulnerabilities were detected in this contract.\n\n")
            else:
                f.write(f"Found {len(rechecked_vulns)} potential vulnerabilities:\n\n")

                # Create a summary table
                f.write("| # | Vulnerability Type | Confidence | Affected Functions |\n")
                f.write("|---|-------------------|------------|--------------------|\n")

                for idx, vuln in enumerate(rechecked_vulns, start=1):
                    vuln_type = vuln.get('vulnerability_type', 'Unknown')
                    try:
                        confidence = float(vuln.get('skeptic_confidence', 0))
                    except (ValueError, TypeError):
                        confidence = 0.0
                    affected = ', '.join(vuln.get('affected_functions', ['Unknown']))
                    f.write(f"| {idx} | {vuln_type} | {confidence:.2f} | {affected} |\n")

                f.write("\n")

            # Detailed vulnerability analysis
            if rechecked_vulns:
                f.write("## Detailed Analysis\n\n")

                for idx, vuln in enumerate(rechecked_vulns, start=1):
                    vuln_type = vuln.get('vulnerability_type', 'Unknown')
                    try:
                        confidence = float(vuln.get('skeptic_confidence', 0))
                    except (ValueError, TypeError):
                        confidence = 0.0

                    f.write(f"### Vulnerability #{idx}: {vuln_type}\n\n")
                    f.write(f"**Confidence:** {confidence:.2f}\n\n")

                    if vuln.get('reasoning'):
                        f.write(f"**Reasoning:**\n\n```\n{vuln.get('reasoning')}\n```\n\n")

                    if vuln.get('validity_reasoning'):
                        f.write(f"**Validation:**\n\n```\n{vuln.get('validity_reasoning')}\n```\n\n")

                    if vuln.get('code_snippet'):
                        f.write(f"**Code Snippet:**\n\n```solidity\n{vuln.get('code_snippet')}\n```\n\n")

                    if vuln.get('affected_functions'):
                        f.write(f"**Affected Functions:** {', '.join(vuln.get('affected_functions'))}\n\n")

                    # Look for a corresponding PoC
                    matching_poc = next((p for p in pocs if p.get("vulnerability", {}).get("vulnerability_type") == vuln_type), None)
                    if matching_poc and matching_poc.get("exploit_plan"):
                        f.write("**Exploit Plan:**\n\n")
                        plan = matching_poc["exploit_plan"]
                        if plan.get("setup_steps"):
                            f.write("*Setup Steps:*\n")
                            for step in plan["setup_steps"]: f.write(f"- {step}\n")
                        if plan.get("execution_steps"):
                            f.write("*Execution Steps:*\n")
                            for step in plan["execution_steps"]: f.write(f"- {step}\n")
                        if plan.get("validation_steps"):
                            f.write("*Validation Steps:*\n")
                            for step in plan["validation_steps"]: f.write(f"- {step}\n")
                        f.write("\n")

                    f.write("---\n\n")

            # PoC information if any were generated
            if pocs:
                f.write("## Proof of Concept Exploits\n\n")

                for idx, poc in enumerate(pocs, start=1):
                    if "poc_data" not in poc: continue # Skip if no PoC data (e.g., skipped generation)

                    vuln = poc['vulnerability']
                    vuln_type = vuln.get('vulnerability_type', 'Unknown')
                    f.write(f"### PoC #{idx}: {vuln_type}\n\n")

                    poc_data = poc["poc_data"]
                    exploit_file = poc_data.get('exploit_file', 'N/A')
                    f.write(f"**File:** `{os.path.basename(exploit_file)}`\n\n")

                    if "execution_results" in poc_data:
                        exec_res = poc_data["execution_results"]
                        if exec_res.get("success"):
                            f.write("**Execution:** ✅ SUCCESS\n\n")
                        elif exec_res.get("success") is False:
                            f.write(f"**Execution:** ❌ FAILED after {exec_res.get('retries', 0)} fix attempts\n")
                            if exec_res.get("error"):
                                f.write(f"**Error:**\n```\n{exec_res.get('error')}\n```\n\n")
                        else:
                             f.write("**Execution:** ❔ SKIPPED\n\n")

                    if poc_data.get("exploit_code"):
                        f.write("**Exploit Code:**\n\n```solidity\n")
                        f.write(poc_data.get("exploit_code"))
                        f.write("\n```\n\n")

                    f.write("---\n\n")

            # Footer with recommendations
            f.write("## Recommendations\n\n")
            f.write("For each identified vulnerability, consider implementing the following mitigations:\n\n")
            found_vuln_types = {v.get('vulnerability_type', '').lower() for v in rechecked_vulns}
            if any('reentrancy' in vt for vt in found_vuln_types): f.write("- **Reentrancy**: Use checks-effects-interactions pattern, ReentrancyGuard.\n")
            if any(term in vt for vt in found_vuln_types for term in ['overflow', 'underflow', 'arithmetic']): f.write("- **Arithmetic**: Use Solidity 0.8+ or SafeMath.\n")
            if any(term in vt for vt in found_vuln_types for term in ['access', 'authorization', 'permission']): f.write("- **Access Control**: Use modifiers (`onlyOwner`), check roles properly.\n")
            if any(term in vt for vt in found_vuln_types for term in ['oracle', 'price']): f.write("- **Oracle Manipulation**: Use TWAP, multiple sources (e.g., Chainlink).\n")
            if any('unchecked' in vt for vt in found_vuln_types): f.write("- **Unchecked Returns**: Check return values of external calls.\n")
            f.write("- **General**: Conduct thorough testing and consider professional audits.\n\n")
            f.write("*This report was generated automatically.*\n")

        print_success(f"Report exported to {output_file}")
    except Exception as e:
        print_error(f"Error writing markdown report to {output_file}: {e}")


# Function to export results to JSON for automated analysis
def export_results_to_json(filepath, results, output_file):
    """Export analysis results to a JSON file"""
    import json

    # Create a serializable results dictionary
    export_data = {
        "contract_path": filepath,
        "rechecked_vulnerabilities": results.get("rechecked_vulnerabilities", []),
        "generated_pocs": []
    }

    # Process PoC data for serialization
    for poc in results.get("generated_pocs", []):
        poc_data_export = {
            "vulnerability": poc.get("vulnerability", {}),
            "exploit_plan": poc.get("exploit_plan", {}),
        }

        if "poc_data" in poc:
            poc_data_orig = poc["poc_data"]
            poc_data_export["poc_data"] = {
                "exploit_file": poc_data_orig.get("exploit_file", ""),
                "execution_command": poc_data_orig.get("execution_command", ""),
            }

            if "execution_results" in poc_data_orig:
                exec_res_orig = poc_data_orig["execution_results"]
                poc_data_export["poc_data"]["execution_results"] = {
                    "success": exec_res_orig.get("success"), # Keep None if skipped
                    "retries": exec_res_orig.get("retries", 0),
                    "error": exec_res_orig.get("error", "")
                }

        export_data["generated_pocs"].append(poc_data_export)

    # Write to file
    try:
        with open(output_file, "w", encoding='utf-8') as f:
            json.dump(export_data, f, indent=2)
        print_success(f"Results exported to {output_file}")
    except Exception as e:
        print_error(f"Error exporting results to JSON file {output_file}: {e}")

if __name__ == "__main__":
    main()
