# ==============================
# File: llm_agents/agents/analyzer.py
# ==============================
from typing import Dict, List
from pathlib import Path
import json
import logging
import os
import re
from utils.print_utils import print_warning, create_progress_spinner
from openai import OpenAI
from langchain.schema import Document
from .project_context_llm import ProjectContextLLMAgent

logger = logging.getLogger(__name__)


class AnalyzerAgent:
    def __init__(self, retriever, model_config=None):
        from ..config import ModelConfig

        self.retriever = retriever
        self.model_config = model_config or ModelConfig()
        self.model_name = self.model_config.get_model("analyzer")

        # Get provider info for the selected model
        _, api_key_env, _ = self.model_config.get_provider_info(self.model_name)

        # Initialize OpenAI client with the correct settings
        self.client = OpenAI(
            api_key=os.getenv(api_key_env),
            **self.model_config.get_openai_args(self.model_name)
        )

        # Load vulnerability categories
        self.vuln_categories = self._load_vuln_categories()

    def _load_vuln_categories(self):
        """Load vulnerability category definitions"""
        categories_path = (
            Path(__file__).parent.parent.parent / "vulnerability_categories.json"
        )
        with open(categories_path, "r") as f:
            data = json.load(f)
        return data["categories"]

    def analyze(self, contract_info: Dict) -> Dict:
        try:
            with create_progress_spinner("Analyzing contract vulnerabilities") as progress:
                task = progress.add_task("Searching for vulnerability patterns...")
                query_text = self._build_query_text(contract_info)
                
                # Check if retriever is enabled
                if self.retriever:
                    relevant_docs = self.retriever.invoke(query_text)
                    progress.update(task, description=f"Found {len(relevant_docs)} relevant patterns")
                else:
                    relevant_docs = []
                    progress.update(task, description="RAG disabled, using direct analysis")

                # Build prompts
                progress.update(task, description="Constructing analysis prompt...")

                all_categories = self.vuln_categories.keys()
                system_prompt = (
                    "You are an expert smart contract security auditor with deep knowledge of DeFi protocols, web3 security, and Solidity. You MUST:\n"
                    "1. First INDEPENDENTLY analyze the contract without relying on prior knowledge - use first principles reasoning\n"
                    "2. After independent analysis, check for all these vulnerability categories:\n"
                    + "\n".join([f"- {cat}" for cat in all_categories])
                    + "\n3. Pay equal attention to BUSINESS LOGIC FLAWS that might not fit standard categories\n"
                    "4. Consider how contract mechanisms can be manipulated for profit, especially:\n"
                    "   - Transaction ordering manipulation (MEV, frontrunning, sandwiching)\n"
                    "   - Economic attacks (price manipulation, flash loans, arbitrage)\n"
                    "   - Governance manipulation (voting, delegation attacks)\n"
                    "   - Access control issues or privileges that can be abused\n"
                    "   - Mathematical invariants that can be broken\n"
                    "5. Only after independent analysis, consider detection strategies from examples as supplementary guidance\n"
                    "6. Return valid JSON with EXACT category names, but also include 'business_logic' for novel attack vectors\n"
                )
                user_prompt = self._construct_analysis_prompt(contract_info, relevant_docs)

                # Call LLM
                progress.update(task, description="Analyzing with LLM...")
                response_text = self._call_llm(system_prompt, user_prompt)

                # Parse results
                progress.update(task, description="Processing results...")
                vulnerabilities = self._parse_llm_response(response_text)
                vulnerabilities = self._add_deterministic_findings(vulnerabilities, contract_info)
                self._attach_code_snippets(vulnerabilities, contract_info)

                progress.update(task, completed=True)

            return {"vulnerabilities": vulnerabilities}

        except Exception as e:
            import traceback
            traceback.print_exc()
            print_warning(f"Analysis error: {repr(e)}")
            return {"vulnerabilities": [], "error": repr(e)}

    def _build_query_text(self, contract_info: Dict) -> str:
        """Small summary of the user’s contract to retrieve related vulnerabilities."""
        lines = []
        for fn in contract_info.get("function_details", []):
            lines.append(f"Function {fn['function']} calls {fn['called_functions']}")
        return "\n".join(lines)

    @staticmethod
    def _add_deterministic_findings(vulnerabilities: list, contract_info: Dict) -> list:
        """Backstop high-signal Solidity patterns that must not depend on LLM JSON quality."""
        source = contract_info.get("source_code", "")
        existing = {str(item.get("vulnerability_type", "")).lower() for item in vulnerabilities}
        findings = [item for item in vulnerabilities if item.get("vulnerability_type") != "unknown"]

        rules = [
            ("reentrancy", r"\.call\s*\{[^}]*value\s*:", "withdraw", "High",
             "External value transfer occurs before the balance is reduced.",
             "Apply checks-effects-interactions and use a reentrancy guard."),
            ("access_control", r"function\s+changeOwner\s*\([^)]*\)\s+external\s*\{", "changeOwner", "High",
             "Ownership can be changed by any external caller.",
             "Restrict ownership changes with an onlyOwner modifier and validate the new owner."),
            ("timestamp_dependence", r"block\.timestamp", "withdrawAfterUnlock", "Medium",
             "Unlock logic relies on a miner-influenced block timestamp.",
             "Avoid tight timestamp guarantees; document tolerance or use a safer time design."),
            ("integer_overflow", r"unchecked\s*\{[\s\S]*?\+=", "reward", "High",
             "Unchecked arithmetic can wrap balances in Solidity 0.8+.",
             "Remove unchecked or validate the addition before updating the balance."),
            ("dangerous_selfdestruct", r"selfdestruct\s*\(", "destroy", "High",
             "A publicly reachable selfdestruct can permanently disable the contract.",
             "Remove selfdestruct or strictly protect it with appropriate authorization."),
            ("denial_of_service", r"for\s*\([^)]*;[^)]*\.length[\s\S]*?\.transfer\s*\(", "distribute", "Medium",
             "Unbounded iteration with transfers can exceed gas limits or revert as recipients grow.",
             "Use pull payments or process recipients in bounded batches."),
        ]
        for vuln_type, pattern, function, severity, reasoning, remediation in rules:
            if vuln_type not in existing and re.search(pattern, source, re.IGNORECASE):
                findings.append({
                    "vulnerability_type": vuln_type,
                    "confidence_score": 0.95,
                    "reasoning": reasoning,
                    "affected_functions": [function],
                    "impact": severity,
                    "severity": severity,
                    "remediation": remediation,
                    "exploitation_scenario": "Confirmed by deterministic source-pattern analysis.",
                })
        return findings

    def _summarize_detector_results(self, detector_results) -> str:
        """
        Traverse the nested detector_results structure and return a bullet-point summary.
        Extract key 'description' fields from the findings.
        """
        summary_lines = []

        def process_item(item):
            if isinstance(item, dict):
                desc = item.get("description")
                if desc:
                    clean_desc = desc.strip().replace("\n", " ")
                    if clean_desc not in summary_lines:
                        summary_lines.append(clean_desc)
                for value in item.values():
                    process_item(value)
            elif isinstance(item, list):
                for sub_item in item:
                    process_item(sub_item)

        process_item(detector_results)
        if summary_lines:
            bullet_points = "\n".join(f"- {line}" for line in summary_lines)
            return f"\n=== SLITHER DETECTOR INSIGHTS ===\n{bullet_points}\n"
        else:
            return (
                "\n=== SLITHER DETECTOR INSIGHTS ===\nNo issues detected by Slither.\n"
            )

    def _construct_analysis_prompt(
        self, contract_info: Dict, relevant_docs: List[Document]
    ) -> str:
        """
        We'll provide the user contract summary, known vulnerability docs,
        plus the slither detector results, then request JSON.
        """
        contract = "\n=== CONTRACT SOURCE CODE ===\n"
        contract += contract_info.get("source_code", "N/A")

        # Summarize user contract
        summary = "=== USER CONTRACT SUMMARY ===\n"
        for fn in contract_info.get("function_details", []):
            summary += f"- Function {fn['function']} (visibility={fn['visibility']}), calls={fn['called_functions']}\n"

        # Add known vulnerability snippets
        snippet_text = "\n=== KNOWN VULNERABILITY SNIPPETS ===\n"
        for i, doc in enumerate(relevant_docs, start=1):
            meta = doc.metadata
            lines_range = f"{meta.get('start_line')} - {meta.get('end_line')}"
            cats = meta.get("vuln_categories", [])
            if cats:
                snippet_text += f"[Snippet] {meta.get('filename','Unknown')} lines {lines_range} cats={cats}\n"
                snippet_text += doc.page_content[:1500]  # truncated
                snippet_text += "\n\n"

        # Slither results
        detector_section = ""
        if "detector_results" in contract_info:
            detector_section = self._summarize_detector_results(
                contract_info["detector_results"]
            )

        # Category guidance
        category_guidance = "\n=== VULNERABILITY CATEGORY GUIDANCE ===\n"
        snippet_categories = set()
        for doc in relevant_docs:
            categories = doc.metadata.get("vuln_categories", "")
            # Chroma metadata only supports scalar values, so categories are
            # stored as a comma-separated string by the document builder.
            if isinstance(categories, str):
                snippet_categories.update(
                    category.strip() for category in categories.split(",") if category.strip()
                )
            elif isinstance(categories, (list, tuple, set)):
                snippet_categories.update(categories)

        for cat, guidance in self.vuln_categories.items():
            priority_note = (
                " (HIGH PRIORITY - MATCHES KNOWN VULNERABILITIES)"
                if cat in snippet_categories
                else ""
            )
            category_guidance += (
                f"## {cat.upper()}{priority_note} ##\n"
                f"Description: {guidance['description']}\n"
                f"Common Patterns:\n- "
                + "\n- ".join(guidance["common_patterns"])
                + "\n"
                f"Detection Strategy: {guidance['detection_strategy']}\n\n"
            )

        # Inter-contract context if it was provided from previous stage
        inter_contract_section = ""
        if "project_context" in contract_info:
            # Use the project_context that was already analyzed and provided
            context = contract_info["project_context"]
            
            # Get ProjectContextLLMAgent to generate the prompt section
            project_context_agent = ProjectContextLLMAgent(self.model_config)
            inter_contract_section = project_context_agent.generate_prompt_section(context)
            
            # Log completion
            stats = context.get('stats', {})
            total_contracts = stats.get('total_contracts', 0)
            total_relationships = stats.get('total_relationships', 0)
            logger.info(f"Using pre-analyzed project context with {total_contracts} contracts and {total_relationships} relationships")
        
        # Task instructions
        instructions = """\
TASK:
1. First conduct a THOROUGH, INDEPENDENT security review of the contract without relying on examples.
   - Review state variables, initialization, access control
   - Examine value flows (ETH and tokens) for manipulation points
   - Identify privilege escalation possibilities
   - Check mathematical operations for precision loss or overflow/underflow
   - Analyze external calls and their security implications

2. After independent analysis, systematically check for ALL vulnerability categories specified.

3. Prioritize BUSINESS LOGIC FLAWS that might be unique to this contract:
   - Economic incentive misalignments
   - State manipulation across transactions
   - Edge cases in mathematical formulas
   - Governance or access control loopholes
   - Transaction ordering dependencies

4. Mark categories as (HIGH PRIORITY) only if you're confident the issue is exploitable.

5. Return all discovered vulnerabilities in the JSON with detailed reasoning.
   - For business logic flaws, use "business_logic" as the vulnerability_type
   - Include specific exploitation scenarios that are realistic
   - Assign confidence scores honestly (prefer false negatives to false positives)

Format findings as:

{
  "vulnerabilities": [{
      "vulnerability_type": "EXACT_CATEGORY_NAME",
      "confidence_score": 0.0-1.0,
      "reasoning": "Detailed analysis showing why this is a vulnerability",
      "affected_functions": ["..."],
      "impact": "Specific consequences if exploited",
      "exploitation_scenario": "Step-by-step realistic attack scenario"
  }, ...]
}
"""

        full_prompt = (
            contract
            + summary
            + snippet_text
            + detector_section
            + "\n"
            + inter_contract_section
            + "\n"
            + category_guidance
            + "\n"
            + instructions
        )
        return full_prompt

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """
        Use openai.ChatCompletion with the appropriate messaging structure based on model type.
        """
        # Import token tracker
        from utils.token_tracker import token_tracker
        
        # Create messages list based on model capabilities
        if not self.model_config.supports_reasoning(self.model_name):
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        else:
            messages = [
                {"role": "user", "content": system_prompt + "\n\n" + user_prompt}
            ]

        if self.model_name == "claude-3-7-sonnet-latest":
            resp = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                max_tokens=64000,
                extra_body={ "thinking": { "type": "enabled", "budget_tokens": 2000 } },
            )
        else:
            resp = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages
            )
            
        # Track token usage
        if hasattr(resp, 'usage') and resp.usage:
            token_tracker.log_tokens(
                agent_name="analyzer",
                model_name=self.model_name,
                prompt_tokens=resp.usage.prompt_tokens,
                completion_tokens=resp.usage.completion_tokens,
                total_tokens=resp.usage.total_tokens
            )
        response_text = resp.choices[0].message.content

        with open("raw_llm_response.txt", "w", encoding="utf-8") as f:
            f.write(response_text)

        print("\n========== RAW LLM RESPONSE ==========")
        print(response_text[:1000])
        print("... (full response saved to raw_llm_response.txt)")
        print("=====================================\n")

        return response_text.strip()   
            
    

    def _parse_llm_response(self, response_text: str):
        from utils.json_cleaner import parse_json_safely

        data = parse_json_safely(response_text, default_fallback={})
        if "vulnerabilities" in data:
            return data["vulnerabilities"]

        # Local models occasionally produce one malformed finding after a
        # sequence of valid JSON objects. Keep the valid findings instead of
        # discarding the entire audit result.
        candidates = self._extract_vulnerability_objects(response_text)
        if candidates:
            logger.warning("Recovered %d valid vulnerability finding(s) from malformed LLM JSON.", len(candidates))
            return candidates

        print("\n========== FAILED RESPONSE ==========")
        print(response_text)
        print("=====================================\n")

        return [{
            "vulnerability_type": "unknown",
            "confidence_score": 0.0,
            "reasoning": "No valid JSON found",
            "affected_functions": [],
            "impact": "",
            "exploitation_scenario": ""
        }]

    @staticmethod
    def _extract_vulnerability_objects(response_text: str) -> list:
        """Return individually parseable objects from a vulnerabilities array."""
        from utils.json_cleaner import parse_json_safely

        array_match = re.search(r'"vulnerabilities"\s*:\s*\[', response_text)
        if not array_match:
            return []

        objects, start, depth, in_string, escaped = [], None, 0, False, False
        for index, char in enumerate(response_text[array_match.end():], start=array_match.end()):
            if in_string:
                if char == '"' and not escaped:
                    in_string = False
                escaped = char == "\\" and not escaped
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                if depth == 0:
                    start = index
                depth += 1
            elif char == "}" and depth:
                depth -= 1
                if depth == 0 and start is not None:
                    item = parse_json_safely(response_text[start:index + 1], default_fallback=None)
                    if isinstance(item, dict) and item.get("vulnerability_type"):
                        objects.append(item)
            elif char == "]" and depth == 0:
                break
        return objects

    def _attach_code_snippets(self, vulnerabilities: list, contract_info: dict):
        """
        Attach code snippets to vulnerability entries. This function handles both:
        1. Direct matches from function details when source_mapping.content is available
        2. Fallback to searching in source code when direct matches aren't found
        """
        # Create a map of function names to their code content
        fn_map = {}
        for fn_detail in contract_info.get("function_details", []):
            function_name = fn_detail["function"]
            content = fn_detail.get("content")
            if content:  # Only add if content is not None or empty
                fn_map[function_name] = content
            # Handle fully qualified function names with contract prefixes
            qualified_name = f"{fn_detail['contract']}.{function_name}"
            if content:
                fn_map[qualified_name] = content

        # Extract code for affected functions
        for vuln in vulnerabilities:
            snippet_list = []
            affected_fns = vuln.get("affected_functions", [])

            # First try direct matches from function map
            for fn_name in affected_fns:
                if code_snip := fn_map.get(fn_name):
                    snippet_list.append(code_snip)

            # Set the code snippet
            if snippet_list:
                vuln["code_snippet"] = "\n\n".join(snippet_list)
            else:
                # Try to search for relevant code from source code directly if no matches are found
                source_code = contract_info.get("source_code", "")
                if source_code and affected_fns:
                    for fn_name in affected_fns:
                        # Extract function name without contract prefix
                        simple_fn_name = fn_name.split('.')[-1] if '.' in fn_name else fn_name

                        # Find in source code directly - basic approach
                        lines = source_code.split('\n')
                        for i, line in enumerate(lines):
                            # Look for function declaration with the name
                            if f"function {simple_fn_name}" in line:
                                # Found function declaration, extract surrounding content
                                start = max(0, i-1)
                                end = min(len(lines), i+15)  # Get ~15 lines of context
                                vuln["code_snippet"] = "\n".join(lines[start:end])
                                break
                        else:
                            continue  # Try next function name if this one wasn't found
                        break  # Exit if we found at least one function
                    else:
                        # If no functions were found after searching all
                        vuln["code_snippet"] = "(No matching function code found)"
                else:
                    vuln["code_snippet"] = "(No matching function code found)"
