# ==============================
# File: llm_agents/agents/skeptic.py
# ==============================
import os
import json
from openai import OpenAI
import re
from utils.print_utils import create_progress_spinner, print_warning

class SkepticAgent:
    """
    The SkepticAgent re-checks each vulnerability to confirm whether it truly applies.
    It outputs a re-ranked or filtered list of vulnerabilities, sorted from highest to lowest confidence.
    """

    def __init__(self, model_config=None):
        from ..config import ModelConfig

        self.model_config = model_config or ModelConfig()
        self.model_name = self.model_config.get_model("skeptic")

        # Get provider info for the selected model
        _, api_key_env, _ = self.model_config.get_provider_info(self.model_name)

        # Initialize OpenAI client with the correct settings
        self.client = OpenAI(
            api_key=os.getenv(api_key_env),
            **self.model_config.get_openai_args(self.model_name)
        )

    def audit_vulnerabilities(self, contract_source: str, vulnerabilities: list) -> list:
        if not vulnerabilities:
            return []

        with create_progress_spinner("Re-checking vulnerabilities") as progress:
            task = progress.add_task("Analyzing...")

            # Build prompts
            system_prompt = """You are a highly critical, business-focused Smart Contract Security Auditor with real-world exploit experience.
    Your role is to carefully evaluate initial vulnerability findings and provide a balanced assessment of their severity and exploitability.

    Consider these factors when reviewing each vulnerability:
    1. Business logic context - How does this vulnerability interact with the specific business purpose of this contract?
    2. Preconditions - What conditions must be met for this to be exploited?
    3. Practical impact - What would be the consequence if exploited?
    4. Implementation details - Is the code actually vulnerable in the way described?
    5. Common vulnerability patterns - Does this match known vulnerability patterns?

    For each alleged vulnerability, determine:
      1) Is it a genuine vulnerability that warrants attention?
      2) Give a REASONABLE confidence score using these guidelines:
         - 0.0-0.2: Definitely not a vulnerability / false positive
         - 0.3-0.5: Unlikely to be exploitable but worth noting
         - 0.6-0.8: Likely a genuine concern requiring attention
         - 0.9-1.0: Critical vulnerability with high certainty
      3) Provide clear reasoning that supports your confidence score

    Especially look for subtle business logic flaws that automated tools or pattern-matching might miss:
    - Economic manipulation (arbitrage, price manipulation)
    - Logical sequence exploits (state manipulation across transactions)
    - Trust assumptions that conflict with incentives
    - Edge cases in mathematical calculations
    - Parameter bounds and invariant violations

    It is okay to be more confident about business logic flaws, as these arise from pure reasoning from the previous agent.
    You should carefully evaluate the categorized vulnerabilities as they arrise from pattern matching.

    Output JSON exactly in the format:
    {
      "rechecked_vulnerabilities": [
        {
          "original_idx": 0,
          "skeptic_confidence": 0.0,
          "validity_reasoning": ""
        },
        ...
      ]
    }
            """
            user_prompt = f"=== CONTRACT SOURCE CODE ===\n{contract_source}\n\n=== REPORTED VULNERABILITIES ===\n"
            for idx, vuln in enumerate(vulnerabilities):
                user_prompt += f"#{idx} => type={vuln.get('vulnerability_type')} code:\n"
                code_snippet = vuln.get("code_snippet") or "(no snippet)"
                user_prompt += f"{code_snippet}\n\n"

            user_prompt += """Please re-check each vulnerability from #0, #1, #2, etc.
    Return a JSON object with the final verdict.
    """
            # Call LLM with appropriate message structure
            if self.model_config.supports_reasoning(self.model_name):
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
            else:
                messages = [
                    {"role": "user", "content": system_prompt + user_prompt}
                ]

            # Import token tracker
            from utils.token_tracker import token_tracker
            
            if self.model_name == "claude-3-7-sonnet-latest":
                resp = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    max_tokens=64000,
                    extra_body={ "thinking": { "type": "enabled", "budget_tokens": 5000 } },
                )
            else:
                resp = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=messages
                )
                
            # Track token usage
            if hasattr(resp, 'usage') and resp.usage:
                token_tracker.log_tokens(
                    agent_name="skeptic",
                    model_name=self.model_name,
                    prompt_tokens=resp.usage.prompt_tokens,
                    completion_tokens=resp.usage.completion_tokens,
                    total_tokens=resp.usage.total_tokens
                )
                
            text_out = resp.choices[0].message.content.strip()

            # Parse results
            progress.update(task, description="Processing results...")
            rechecked = self._parse_response(text_out)

            # Update vulnerabilities with skeptic results
            for item in rechecked:
                idx = item.get("original_idx")
                if idx is not None and 0 <= idx < len(vulnerabilities):
                    vulnerabilities[idx]["skeptic_confidence"] = item.get(
                        "skeptic_confidence", 0.0
                    )
                    vulnerabilities[idx]["validity_reasoning"] = item.get(
                        "validity_reasoning", ""
                    )


            progress.update(task, completed=True)

        return sorted(vulnerabilities, key=lambda x: x.get("skeptic_confidence", 0), reverse=True)

    def _parse_response(self, text_out: str) -> list:
        try:
            data = json.loads(text_out)
            return data.get("rechecked_vulnerabilities", [])
        except json.JSONDecodeError:
            # Try extracting JSON from markdown code block
            if match := re.search(r"```(?:json)?(.*?)```", text_out, re.DOTALL):
                try:
                    return json.loads(match.group(1).strip()).get("rechecked_vulnerabilities", [])
                except:
                    print_warning("Failed to parse JSON from code block")
            return []
