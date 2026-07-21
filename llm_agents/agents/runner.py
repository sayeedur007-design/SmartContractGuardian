# ==============================
# File: llm_agents/agents/runner.py
# ==============================
import os
import subprocess
import re
from typing import Dict, Tuple, List, Optional
from openai import OpenAI

from ..config import ModelConfig
from utils.print_utils import print_step, print_warning, print_success, create_progress_spinner

class ExploitRunner:
    """
    The ExploitRunner executes and fixes Foundry test contracts.
    It automatically runs the generated PoC tests, detects errors,
    and attempts to fix them using the same model that generated them.
    """

    def __init__(self, model_config=None):
        from ..config import ModelConfig

        self.model_config = model_config or ModelConfig()
        self.model_name = self.model_config.get_model("generator")

        # Get provider info for the selected model
        _, api_key_env, _ = self.model_config.get_provider_info(self.model_name)

        # Initialize OpenAI client with the correct settings
        self.client = OpenAI(
            api_key=os.getenv(api_key_env),
            **self.model_config.get_openai_args(self.model_name)
        )
        self.max_retries = 3

    def run_and_fix_exploit(self, poc_data: Dict) -> Dict:
        """
        Run the exploit test and fix it if it fails.

        Args:
            poc_data: Dictionary containing exploit file path and execution command

        Returns:
            Dictionary with execution results and fixed code if applicable
        """
        import shutil

        # Get file path and execution command
        exploit_file = poc_data.get("exploit_file")
        execution_command = poc_data.get("execution_command")

        if not exploit_file or not os.path.exists(exploit_file):
            return {"success": False, "error": "Exploit file not found", "output": ""}

        # Isolate the current PoC file to prevent compilation errors from other files
        test_dir = os.path.join("exploit", "src", "test")
        backup_dir = os.path.join("exploit", "src", "test_backup")
        os.makedirs(backup_dir, exist_ok=True)
        
        current_filename = os.path.basename(exploit_file)
        moved_files = []

        try:
            # Move all other PoC files to the backup directory
            if os.path.exists(test_dir):
                for f in os.listdir(test_dir):
                    if f.startswith("PoC_") and f.endswith(".sol") and f != current_filename:
                        src_path = os.path.join(test_dir, f)
                        dst_path = os.path.join(backup_dir, f)
                        try:
                            shutil.move(src_path, dst_path)
                            moved_files.append((dst_path, src_path))
                        except Exception as move_err:
                            print_warning(f"Could not temporarily move {f}: {move_err}")

            with create_progress_spinner("Running exploit test") as progress:
                task = progress.add_task("Executing test...")

                # Initialize results
                success = False
                output = ""
                error_message = ""
                retry_count = 0
                fixed_code = None

                # Keep trying until success or max retries reached
                while not success and retry_count < self.max_retries:
                    if retry_count > 0:
                        progress.update(task, description=f"Retry #{retry_count}: Running test again...")

                    # Run the test
                    success, output, error_message = self._execute_test(execution_command)

                    # If test failed, try to fix it
                    if not success:
                        progress.update(task, description=f"Test failed. Attempting to fix code (try {retry_count + 1}/{self.max_retries})...")
                        fixed_code = self._fix_test_code(exploit_file, output, error_message)

                        if fixed_code:
                            # Clean up markdown code blocks if the fix response has them
                            if fixed_code.startswith("```") and fixed_code.endswith("```"):
                                match = re.search(r"```(?:solidity)?\s*([\s\S]*?)\s*```", fixed_code)
                                if match:
                                    fixed_code = match.group(1).strip()
                            elif "```" in fixed_code:
                                match = re.search(r"```(?:solidity)?\s*([\s\S]*?)\s*```", fixed_code)
                                if match:
                                    fixed_code = match.group(1).strip()

                            # Save the fixed code
                            with open(exploit_file, 'w', encoding='utf-8') as f:
                                f.write(fixed_code)
                            progress.update(task, description="Fixed code saved. Running test again...")
                        else:
                            progress.update(task, description="Could not fix code. Moving to next retry...")

                    retry_count += 1

                # Update progress based on final result
                if success:
                    progress.update(task, description="Test executed successfully!", completed=True)
                else:
                    progress.update(task, description="Test failed after all retries", completed=True)

        finally:
            # Restore all moved files
            for dst_path, src_path in moved_files:
                if os.path.exists(dst_path):
                    try:
                        shutil.move(dst_path, src_path)
                    except Exception as restore_err:
                        # If destination already exists, just remove backup
                        if os.path.exists(src_path):
                            os.remove(dst_path)
                        else:
                            print_warning(f"Could not restore {os.path.basename(src_path)}: {restore_err}")

        # Return results
        return {
            "success": success,
            "output": output,
            "error": error_message if not success else "",
            "fixed_code": fixed_code if fixed_code and not success else None,
            "file_path": exploit_file,
            "retries": retry_count - 1  # Actual retries (-1 because first attempt isn't a retry)
        }

    def _execute_test(self, command: str) -> Tuple[bool, str, str]:
        """
        Execute a Foundry test command and capture the output.

        Args:
            command: Forge test command to execute

        Returns:
            Tuple of (success, output, error_message)
        """
        try:
            # Execute the command
            result = subprocess.run(
                command,
                shell=True,
                cwd=os.path.join(os.getcwd(), "exploit"),
                capture_output=True,
                text=True
            )

            # Get complete output
            output = result.stdout + "\n" + result.stderr

            # Check if the test passed
            if result.returncode == 0 and "FAIL" not in result.stdout:
                return True, output, ""

            # Extract error message
            error_pattern = r"(Error|Fail|Revert|Panic|Error:\s*.*|.*reverted.*)"
            error_matches = re.findall(error_pattern, output, re.IGNORECASE)
            error_message = "\n".join(error_matches) if error_matches else "Unknown error"

            return False, output, error_message

        except Exception as e:
            return False, "", f"Error executing test: {str(e)}"

    def _fix_test_code(self, file_path: str, output: str, error_message: str) -> Optional[str]:
        """
        Use the model to fix the test code based on the error message.

        Args:
            file_path: Path to the test file
            output: Complete output from the test execution
            error_message: Extracted error message

        Returns:
            Fixed code as string or None if it couldn't be fixed
        """
        try:
            # Read the current file content
            with open(file_path, 'r') as f:
                current_code = f.read()

            # Create a prompt to fix the code
            prompt = f"""
I need to fix a Foundry smart contract test that is failing.

Here's the original test code:
```solidity
{current_code}
```

Here's the error output when running the test:
```
{error_message}
```

Full output:
```
{output[:2000]}  # Truncate to avoid token limits
```

Please fix the code to make the test pass. Common issues to check:
1. Missing funds for transactions (vm.deal)
2. Incorrect function calls or parameters
3. Incorrect expectation of return values
4. Arithmetic errors like overflow/underflow
5. Invalid state assumptions
6. Problems with balanceLog modifier implementation

IMPORTANT: Return ONLY the complete fixed code with no explanation or markdown.
"""
            # Create appropriate messages based on model type
            if self.model_config.supports_reasoning(self.model_name):
                messages = [
                    {"role": "system", "content": "You are an expert at fixing Foundry test contracts. Your task is to fix a failing test by analyzing error messages and correcting the code."},
                    {"role": "user", "content": prompt}
                ]
            else:
                messages = [
                    {"role": "user", "content": prompt}
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

            fixed_code = resp.choices[0].message.content.strip()

            # Clean up the response if it has markdown code blocks
            if fixed_code.startswith("```") and fixed_code.endswith("```"):
                # Extract code from markdown
                fixed_code = re.search(r"```(?:solidity)?\s*([\s\S]*?)\s*```", fixed_code).group(1)

            return fixed_code

        except Exception as e:
            print_warning(f"Error fixing test code: {str(e)}")
            return None
