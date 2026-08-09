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
from utils.function_identifiers import known_function_ids
from eth_utils import keccak

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
            contract_name = contract_info.get("target_contract", {}).get("name") or next(
                (detail.get("contract") for detail in contract_info.get("function_details", []) if detail.get("contract")),
                "<unknown>",
            )
            logger.info(
                "Analyzer input: source_file=%s contract=%s source_bytes=%d functions=%d",
                contract_info.get("target_contract", {}).get("path", "<unknown>"),
                contract_name,
                len(contract_info.get("source_code", "")),
                len(contract_info.get("function_details", [])),
            )
            with create_progress_spinner("Analyzing contract vulnerabilities") as progress:
                task = progress.add_task("Searching for vulnerability patterns...")
                query_text = self._build_query_text(contract_info)
                
                # Check if retriever is enabled
                if self.retriever:
                    relevant_docs = self.retriever.invoke(query_text)
                    logger.info("Analyzer RAG results: %d", len(relevant_docs))
                    progress.update(task, description=f"Found {len(relevant_docs)} relevant patterns")
                else:
                    relevant_docs = []
                    logger.info("Analyzer RAG results: 0 (disabled)")
                    progress.update(task, description="RAG disabled, using direct analysis")

                # Build prompts
                progress.update(task, description="Constructing analysis prompt...")

                user_prompt = self._construct_analysis_prompt(contract_info, relevant_docs)

                # Call the local LLM for broad review, but never discard
                # deterministic evidence when the local service is unavailable.
                progress.update(task, description="Analyzing with LLM...")
                # Optimized system prompt for local 7B coder model
                system_prompt = (
                    "You are a source-grounded Solidity security auditor. Return only valid JSON. "
                    "Perform a structured audit in this exact order: Access Control; External Calls; State Changes; "
                    "Reentrancy; Arithmetic; Timestamp; Randomness; Business Logic; Denial of Service; Selfdestruct. "
                    "For every accepted finding, cite the affected function and explain the concrete source-level condition, "
                    "attacker capability, and impact. Do not infer code, functions, modifiers, or state that is absent from the source. "
                    "Do not report a category merely because a keyword occurs; report it only when the surrounding logic creates a security-relevant condition. "
                    "Use exact function IDs from the supplied summary and calibrate confidence conservatively."
                )
                try:
                    response_text = self._call_llm(system_prompt, user_prompt)
                    logger.info("Analyzer raw LLM response: %s", response_text)
                    vulnerabilities = self._parse_llm_response(response_text)
                    logger.info("Analyzer parsed LLM findings: %d", len(vulnerabilities))
                except Exception as exc:
                    logger.warning("Local LLM analysis unavailable; continuing with deterministic findings: %s", exc)
                    print_warning(f"Local LLM analysis unavailable; using verified static findings: {exc}")
                    vulnerabilities = []

                # Parse results
                progress.update(task, description="Processing results...")
                vulnerabilities = self._add_deterministic_findings(vulnerabilities, contract_info)
                logger.info("Analyzer findings after source/static evidence merge: %d", len(vulnerabilities))
                vulnerabilities = self._validate_findings(vulnerabilities, contract_info)
                vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)
                self._attach_code_snippets(vulnerabilities, contract_info)
                logger.info("Analyzer final findings: %s", [v.get("vulnerability_type") for v in vulnerabilities])

                progress.update(task, completed=True)

            return {"vulnerabilities": vulnerabilities}

        except Exception as e:
            import traceback
            traceback.print_exc()
            print_warning(f"Analysis error: {repr(e)}")
            return {"vulnerabilities": [], "error": repr(e)}

    def _deduplicate_vulnerabilities(self, vulnerabilities: list) -> list:
        """Remove redundant findings of the same type in the same functions."""
        merged = {}
        for v in vulnerabilities:
            v_type = v.get("vulnerability_type", "").lower()
            # Sort affected functions for consistent keys
            affected = sorted(v.get("affected_functions", []))
            # Create a unique key based on type and affected functions
            key = (v_type, tuple(affected))
            
            current = merged.get(key)
            if current is None:
                merged[key] = dict(v)
                continue
            current_confidence = self._confidence_value(current.get("confidence_score"))
            new_confidence = self._confidence_value(v.get("confidence_score"))
            stronger, supporting = (v, current) if new_confidence > current_confidence else (current, v)
            merged[key] = dict(stronger)
            supporting_reason = str(supporting.get("reasoning", "")).strip()
            if supporting_reason and supporting_reason not in merged[key].get("reasoning", ""):
                merged[key]["reasoning"] = (
                    f"{merged[key].get('reasoning', '').strip()} Supporting evidence: {supporting_reason}"
                ).strip()
        return list(merged.values())

    @staticmethod
    def _confidence_value(value) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError):
            return 0.0

    def _build_query_text(self, contract_info: Dict) -> str:
        """Small summary of the user’s contract to retrieve related vulnerabilities."""
        lines = []
        for fn in contract_info.get("function_details", []):
            lines.append(f"Function {fn['function_id']} calls {fn['called_functions']}")
        return "\n".join(lines)

    @staticmethod
    def _add_deterministic_findings(vulnerabilities: list, contract_info: Dict) -> list:
        """Merge direct source and static evidence that must not depend on LLM output.

        This deliberately works per externally callable function.  A contract-wide
        ``onlyOwner`` search is unsafe: one protected function must not protect an
        unrelated public function.
        """
        existing = {str(item.get("vulnerability_type", "")).lower() for item in vulnerabilities}
        findings = [item for item in vulnerabilities if item.get("vulnerability_type") != "unknown"]
        details = AnalyzerAgent._source_function_details(contract_info)

        def protected(detail):
            modifiers = " ".join(detail.get("modifiers", []) or [])
            body = detail.get("content", "") or ""
            return bool(re.search(
                r"(?:only(?:owner|admin|role)|auth|authorized|admin|role)", modifiers, re.I
            ) or re.search(
                r"(?:onlyOwner|onlyRole|hasRole|_checkRole|require\s*\([^;]*(?:msg\.sender\s*==\s*\w+|\w+\s*==\s*msg\.sender)|if\s*\([^)]*(?:msg\.sender\s*!=|!hasRole))",
                body, re.I
            ))

        def public_or_external(detail):
            return str(detail.get("visibility", "")).lower() in {"public", "external"}

        def privileged_write(detail):
            body = detail.get("content", "") or ""
            # Assignment to a privilege-bearing state variable is a privileged
            # administration operation.  User-owned balance writes are excluded.
            return bool(re.search(
                r"\b(?:owner|admin(?:istrator)?|controller|operator|privileged|roles?)\b\s*(?:\[[^\]]+\])?\s*=",
                body, re.I
            ))

        direct_rules = [
            ("access_control", 0.90, "High", "Restrict the privileged operation with an authorization check.",
             lambda detail: public_or_external(detail) and privileged_write(detail) and not protected(detail),
             "An externally callable function changes privileged state without an authorization check."),
            ("dangerous_selfdestruct", 0.95, "High", "Remove selfdestruct or strictly protect it with authorization.",
             lambda detail: public_or_external(detail) and re.search(r"\bselfdestruct\s*\(", detail.get("content", "") or "", re.I) and not protected(detail),
             "An externally callable function reaches selfdestruct without an authorization check."),
        ]
        for vuln_type, confidence, severity, remediation, predicate, evidence in direct_rules:
            if vuln_type in existing:
                continue
            affected = [detail["function_id"] for detail in details if predicate(detail)]
            if affected:
                findings.append({
                    "vulnerability_type": vuln_type, "confidence_score": confidence,
                    "reasoning": f"Deterministic source evidence: {evidence}",
                    "affected_functions": affected, "impact": severity, "severity": severity,
                    "remediation": remediation,
                    "exploitation_scenario": "Any account can invoke the affected externally callable function.",
                })
                existing.add(vuln_type)

        # Slither is an independent signal.  Preserve its high-signal suicidal
        # result even when a model returns an empty list; direct source checks
        # above remain the authority for the affected function and remediation.
        static_descriptions = AnalyzerAgent._detector_descriptions(contract_info.get("detector_results", []))
        logger.info("Analyzer static-analysis findings: %s", static_descriptions)
        if "dangerous_selfdestruct" not in existing and any(
            re.search(r"\b(?:suicid(?:al|e)?|selfdestruct|destruct)\b", description, re.I)
            for description in static_descriptions
        ):
            affected = [detail["function_id"] for detail in details if re.search(r"\bselfdestruct\s*\(", detail.get("content", ""), re.I)]
            if affected:
                findings.append({
                    "vulnerability_type": "dangerous_selfdestruct", "confidence_score": 0.90,
                    "reasoning": "Static-analysis evidence: Slither reported an unrestricted destruction path. " + static_descriptions[0],
                    "affected_functions": affected, "impact": "High", "severity": "High",
                    "remediation": "Remove selfdestruct or strictly protect it with authorization.",
                    "exploitation_scenario": "Any account can invoke the reported destruction path.",
                })
                existing.add("dangerous_selfdestruct")

        rules = [
            ("reentrancy", 0.95, "High", "Apply checks-effects-interactions and a reentrancy guard.",
             lambda text: re.search(r"\.call\s*\{[^}]*value\s*:", text, re.I) and re.search(r"\.call[\s\S]*?(?:balances|\w+)\s*\[?[^;]*[-+]?=", text, re.I)),
            ("timestamp_dependence", 0.65, "Medium", "Avoid using miner-influenced time in security-sensitive decisions.",
             lambda text: re.search(r"block\.timestamp", text) and re.search(r"(?:require|if|keccak|random|winner|payout|transfer|call|=)\s*[\s\S]{0,120}block\.timestamp|block\.timestamp[\s\S]{0,120}(?:require|if|keccak|random|winner|payout|transfer|call|=)", text, re.I)),
            ("integer_overflow", 0.75, "Medium", "Remove unchecked arithmetic or validate bounds before state updates.",
             lambda text: re.search(r"unchecked\s*\{[\s\S]*?(?:\+\+|--|\+=|-=|\*=)", text, re.I)),
            ("denial_of_service", 0.70, "Medium", "Use pull payments or bounded batches for recipient processing.",
             lambda text: re.search(r"for\s*\([^)]*;[^)]*\.length[\s\S]*?\.(?:transfer|send|call)\s*\(", text, re.I)),
        ]
        for vuln_type, confidence, severity, remediation, predicate in rules:
            if vuln_type in existing:
                continue
            affected = [detail["function_id"] for detail in details if predicate(detail.get("content") or "")]
            if not affected:
                continue
            findings.append({
                "vulnerability_type": vuln_type, "confidence_score": confidence,
                "reasoning": f"Deterministic source evidence found in {', '.join(affected)}.",
                "affected_functions": affected, "impact": severity, "severity": severity,
                "remediation": remediation, "exploitation_scenario": "Confirmed by function-scoped deterministic source analysis.",
            })
        return findings

    @staticmethod
    def _detector_descriptions(detector_results) -> list:
        """Extract Slither result text without assuming a specific result shape."""
        descriptions = []

        def visit(value):
            if isinstance(value, dict):
                for key in ("description", "check", "markdown"):
                    if isinstance(value.get(key), str):
                        descriptions.append(value[key].replace("\n", " ").strip())
                for nested in value.values():
                    visit(nested)
            elif isinstance(value, (list, tuple)):
                for nested in value:
                    visit(nested)

        visit(detector_results)
        return list(dict.fromkeys(description for description in descriptions if description))

    @staticmethod
    def _source_function_details(contract_info: Dict) -> list:
        """Return function metadata, falling back to the uploaded source when needed."""
        details = [dict(detail) for detail in contract_info.get("function_details", [])]
        if details and all(detail.get("content") for detail in details):
            return details

        source = contract_info.get("source_code", "")
        by_name = {detail.get("function"): detail for detail in details if detail.get("function")}
        pattern = re.compile(r"function\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*([^\{;]*)\{", re.I)
        for match in pattern.finditer(source):
            depth, index = 1, match.end()
            while index < len(source) and depth:
                depth += (source[index] == "{") - (source[index] == "}")
                index += 1
            header = match.group(2)
            name = match.group(1)
            detail = dict(by_name.get(name, {}))
            detail.setdefault("function_id", f"{name}()")
            detail.setdefault("function", name)
            detail["visibility"] = "external" if re.search(r"\bexternal\b", header) else ("public" if re.search(r"\bpublic\b", header) else detail.get("visibility", ""))
            detail["content"] = source[match.start():index]
            details = [item for item in details if item.get("function") != name] + [detail]
        return details

    @staticmethod
    def _normalize_function_reference_for_lookup(value, allowed: set,
                                                 function_details: list = None,
                                                 source_code: str = "") -> str | None:
        """Resolve an LLM function reference to a known canonical function ID.

        LLMs occasionally append analysis-specific identifiers (for example,
        ``withdraw(uint256)_0x6d9485e7``).  Those identifiers are not part of a
        Solidity ABI signature, so they must be removed before matching.  This
        method is deliberately lookup-only: callers retain the original value
        for logs and report output.

        Bare names and ``()`` are resolved only when the target has a single
        overload with that name.  This prevents a generated suffix from
        accidentally selecting the wrong overloaded function.
        """
        if not isinstance(value, str):
            return None

        candidate = value.strip()
        if not candidate:
            return None

        details = function_details or []

        # Models commonly cite static-analysis locations (for example,
        # ``OwnershipBug.sol#11``).  Resolve those against Slither's source
        # line ranges before attempting name matching; this also disambiguates
        # overloaded and inherited declarations.
        line_match = re.search(r"#(?:line:)?(\d+)$", candidate, re.I)
        if line_match:
            line = int(line_match.group(1))
            matches = [
                detail.get("function_id") for detail in details
                if detail.get("function_id")
                and detail.get("start_line") is not None
                and detail.get("end_line") is not None
                and int(detail["start_line"]) <= line <= int(detail["end_line"])
            ]
            if len(matches) == 1:
                logger.info("Mapped affected-function reference %r by line %d to %s", value, line, matches[0])
                return matches[0]
            logger.info("Could not uniquely map affected-function reference %r by line %d", value, line)

        # Support byte/character offsets emitted by AST and compiler tools.
        offset_match = re.search(r"(?:#|@|offset:|byte:)(\d+)$", candidate, re.I)
        if offset_match and source_code:
            offset = int(offset_match.group(1))
            line_starts = [0]
            line_starts.extend(index + 1 for index, char in enumerate(source_code) if char == "\n")
            matches = []
            for detail in details:
                if not detail.get("function_id") or detail.get("start_line") is None or detail.get("end_line") is None:
                    continue
                start_line, end_line = int(detail["start_line"]), int(detail["end_line"])
                if start_line < 1 or end_line > len(line_starts):
                    continue
                start = line_starts[start_line - 1]
                end = line_starts[end_line] if end_line < len(line_starts) else len(source_code)
                if start <= offset < end:
                    matches.append(detail["function_id"])
            if len(matches) == 1:
                logger.info("Mapped affected-function reference %r by byte offset %d to %s", value, offset, matches[0])
                return matches[0]
            logger.info("Could not uniquely map affected-function reference %r by byte offset %d", value, offset)

        # Contract qualification is presentation metadata, not part of the
        # ABI-style IDs stored in ``allowed``.
        short_name = candidate.rsplit(".", 1)[-1].replace(" ", "")

        # Preserve contract qualification when it is supplied.  It is needed
        # to distinguish inherited declarations with matching signatures.
        qualified_match = re.search(r"(?:^|[.:])([A-Za-z_]\w*)\.([A-Za-z_]\w*(?:\([^)]*\))?)$", candidate.replace(" ", ""))
        if qualified_match:
            contract_name, function_ref = qualified_match.groups()
            qualified = [
                detail.get("function_id") for detail in details
                if str(detail.get("contract", "")).lower() == contract_name.lower()
                and detail.get("function_id")
                and (detail["function_id"] == function_ref or detail["function_id"].split("(", 1)[0] == function_ref.rstrip("()"))
            ]
            if len(qualified) == 1:
                logger.info("Mapped qualified affected-function reference %r to %s", value, qualified[0])
                return qualified[0]

        # Strip trailing analysis/compiler artifacts, but only when they are
        # separated from the function reference.  Supported artifacts include
        # hex hashes, numeric temporary IDs, UUID-like hex IDs, and long
        # generated hashes.  Repeating the substitution handles compound IDs.
        artifact_suffix = re.compile(
            r"(?:[_$#@:]+(?:0x[0-9a-f]+|[0-9]+|[0-9a-f]{8,}|[a-z0-9]{16,}|"
            r"(?:tmp|temp|id|function|fn|compiler)[_-]?[a-z0-9]+))+$",
            re.IGNORECASE,
        )
        normalized = artifact_suffix.sub("", short_name)

        if normalized in allowed:
            logger.info("Mapped affected-function reference %r directly to %s", value, normalized)
            return normalized

        # A four-byte ABI selector is enough to identify a non-overloaded
        # signature.  Some models surface that selector instead of the
        # human-readable function ID supplied in the prompt.
        selector = normalized.lower()
        if re.fullmatch(r"0x[0-9a-f]{8}", selector):
            matches = [
                function_id for function_id in allowed
                if "0x" + keccak(text=function_id).hex()[:8] == selector
            ]
            if len(matches) == 1:
                logger.info("Mapped selector %r to %s", value, matches[0])
                return matches[0]

        if re.fullmatch(r"0x[0-9a-f]{64}", selector):
            matches = [
                function_id for function_id in allowed
                if "0x" + keccak(text=function_id).hex() == selector
            ]
            if len(matches) == 1:
                logger.info("Mapped function-signature hash %r to %s", value, matches[0])
                return matches[0]

        name = normalized.split("(", 1)[0]
        matches = [function_id for function_id in allowed if function_id.split("(", 1)[0] == name]
        # Signature-less references (including ``withdraw()``) are only safe
        # when the contract has a single overload with that name.
        if len(matches) == 1 and ("(" not in normalized or normalized.endswith("()")):
            logger.info("Mapped affected-function reference %r by name to %s", value, matches[0])
            return matches[0]
        logger.info("Unable to map affected-function reference %r", value)
        return None

    @classmethod
    def _normalize_affected_functions_for_lookup(cls, values, allowed: set,
                                                 function_details: list = None,
                                                 source_code: str = "") -> List[str]:
        """Return unique canonical IDs for lookup without changing report labels."""
        normalized = []
        for value in values or []:
            resolved = cls._normalize_function_reference_for_lookup(
                value, allowed, function_details, source_code
            )
            if resolved and resolved not in normalized:
                normalized.append(resolved)
        return normalized

    @staticmethod
    def _validate_findings(vulnerabilities: list, contract_info: Dict) -> list:
        """Validate references without discarding otherwise valid findings."""
        details = contract_info.get("function_details", [])
        # Constructors, fallback, and receive functions are valid source
        # targets even though the PoC-specific ID helper excludes them.
        allowed = {detail.get("function_id") for detail in details if detail.get("function_id")}
        validated = []
        for finding in vulnerabilities:
            if not isinstance(finding, dict) or not finding.get("vulnerability_type"):
                continue
            affected = AnalyzerAgent._normalize_affected_functions_for_lookup(
                finding.get("affected_functions", []), allowed, details, contract_info.get("source_code", "")
            )
            item = dict(finding)
            if affected:
                # Use canonical IDs downstream so snippets, reviewer prompts,
                # and generation all refer to the actual Solidity function.
                item["affected_functions"] = affected
            else:
                # Hashes, addresses, and opaque IDs cannot always be mapped
                # back to a source declaration. Preserve them for the
                # generator rather than degrading useful evidence to [].
                logger.warning(
                    "Keeping finding %r with unresolved affected functions %r",
                    finding.get("vulnerability_type"), finding.get("affected_functions"),
                )
                item["affected_functions"] = list(finding.get("affected_functions") or [])
            validated.append(item)
        return validated

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
            summary += f"- Function {fn['function_id']} (visibility={fn['visibility']}), modifiers={fn.get('modifiers', [])}, calls={fn['called_functions']}\n"

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
      "affected_functions": ["EXACT_FUNCTION_ID_FROM_USER_CONTRACT_SUMMARY"],
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

        data = parse_json_safely(response_text, default_fallback={}, log_failure=False)
        if "vulnerabilities" in data:
            return data["vulnerabilities"]

        # Local models occasionally produce one malformed finding after a
        # sequence of valid JSON objects. Keep the valid findings instead of
        # discarding the entire audit result.
        candidates = self._extract_vulnerability_objects(response_text)
        if candidates:
            # Recovery is an expected compatibility path for local models; the
            # validated findings are retained and no parsing failure reaches a
            # caller, so this must not be reported as a runtime warning.
            logger.info("Recovered %d valid vulnerability finding(s) from malformed LLM JSON.", len(candidates))
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
                    item = parse_json_safely(response_text[start:index + 1], default_fallback=None, log_failure=False)
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
        print("\n========== FUNCTION MAP ==========")
        for fn in contract_info.get("function_details", []):
            print(
                fn.get("function"),
                "|",
                fn.get("function_id"),
                "| content:",
                fn.get("content") is not None
            )
        print("=================================\n")
        for fn_detail in contract_info.get("function_details", []):
            function_name = fn_detail["function"]
            function_id = fn_detail.get("function_id", function_name)
            content = fn_detail.get("content")

            if not content:
                continue

            fn_map[function_name] = content
            fn_map[function_id] = content

            fn_map[f"{fn_detail['contract']}.{function_name}"] = content
            fn_map[f"{fn_detail['contract']}.{function_id}"] = content

        # Extract code for affected function
        allowed_function_ids = known_function_ids(contract_info.get("function_details", []))
        for vuln in vulnerabilities:
            snippet_list = []
            affected_fns = vuln.get("affected_functions", [])
            print("\n========== VULNERABILITY ==========")
            print(vuln.get("vulnerability_type"))
            print("Affected:", affected_fns)
            print("Available keys:", list(fn_map.keys())[:20])
            print("==================================\n")

            # First try direct matches from function map
            for function_id in self._normalize_affected_functions_for_lookup(
                affected_fns, allowed_function_ids
            ):
                if code_snip := fn_map.get(function_id):
                    snippet_list.append(code_snip)

            # Set the code snippet
            if snippet_list:
                vuln["code_snippet"] = "\n\n".join(snippet_list)
            else:
                # Try to search for relevant code from source code directly if no matches are found
                source_code = contract_info.get("source_code", "")
                if source_code and affected_fns:
                    for function_id in self._normalize_affected_functions_for_lookup(
                        affected_fns, allowed_function_ids
                    ):
                        simple_fn_name = function_id.split('(', 1)[0]

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
