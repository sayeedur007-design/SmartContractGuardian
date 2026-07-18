# llm_agents/agents/generator.py

import time
import os
import json
from typing import Dict, List, Optional
from openai import OpenAI
from utils.print_utils import create_progress_spinner, print_warning, print_success

class GeneratorAgent:
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

    def generate(self, exploit_plan: Dict) -> Dict:
        """
        Generate a complete exploit based on the provided exploit plan.

        Args:
            exploit_plan: Contains the vulnerability information and exploit steps

        Returns:
            Dictionary with the exploit test contract and execution information
        """
        # Extract vulnerability type and other information
        vuln_info = exploit_plan.get("vulnerability", {})
        vuln_type = vuln_info.get("vulnerability_type", "unknown")

        # Generate the PoC contract
        contract_code = self.generate_poc_contract(vuln_info, exploit_plan.get("exploit_plan", {}))

        # Save the contract to a file
        filename = self.save_poc_locally(contract_code, vuln_type)
        filename_for_command = filename

        filename_parts = filename.split("/", 1)
        if len(filename_parts) > 1:
            filename_for_command = '.' + '/' + filename_parts[1]

        return {
            "exploit_code": contract_code,
            "exploit_file": filename,
            "execution_command": f"forge test -vv --match-path {filename_for_command}"
        }

    def generate_poc_contract(self, vulnerability_info: Dict, exploit_plan: Dict) -> str:
        """
        Generate a custom Foundry test contract for the specific vulnerability

        Args:
            vulnerability_info: Information about the vulnerability
            exploit_plan: The steps to exploit the vulnerability

        Returns:
            Complete Solidity code for the Proof of Concept
        """
        # Get the vulnerability type and details
        vuln_type = vulnerability_info.get("vulnerability_type", "unknown")
        affected_functions = self._extract_relevant_functions(vulnerability_info)
        reasoning = vulnerability_info.get("reasoning", "No reasoning provided")
        code_snippet = vulnerability_info.get("code_snippet", "// No code snippet provided")

        # Parse the exploit steps
        setup_steps = self._parse_steps(exploit_plan.get("setup_steps", []))
        execution_steps = self._parse_steps(exploit_plan.get("execution_steps", []))
        validation_steps = self._parse_steps(exploit_plan.get("validation_steps", []))

        # Use OpenAI to generate a custom PoC based on the vulnerability details
        prompt = f"""
You are a smart contract security educator. Create a complete Foundry test contract that demonstrates the following vulnerability FOR EDUCATIONAL PURPOSES ONLY:

Vulnerability Type: {vuln_type}
Affected Functions: {', '.join(affected_functions)}
Reasoning: {reasoning}
Code Snippet:
```solidity
{code_snippet}
```

Educational Demonstration Plan:
Setup Steps:
{setup_steps}

Demonstration Steps:
{execution_steps}

Validation Steps:
{validation_steps}

IMPORTANT FOUNDRY TEST REQUIREMENTS:
1. Import basetest.sol from the current directory: `import "./basetest.sol";`
2. Your contract must extend BaseTestWithBalanceLog: `contract YourTest is BaseTestWithBalanceLog`
3. In the setUp() function, ensure the test contract has enough ETH: `vm.deal(address(this), 100 ether);`
4. Use the balanceLog modifier on your test function: `function testExploit() public balanceLog`
5. In the testExploit function, ensure the test address/contract has enough ETH: `vm.deal(address(this), 10 ether);`
6. Check return values from all external calls and handle errors properly

The educational test contract should:
1. Be a complete, compilable Solidity file using Foundry's Test framework
2. Include all necessary setup to demonstrate the vulnerability concept
3. Show how the vulnerability works with sample code - THIS IS PURELY FOR EDUCATIONAL PURPOSES
4. Provide clear comments explaining the vulnerability and how to prevent it
5. Define all needed interfaces for external contracts
6. Use realistic but safe values and parameters
7. Include educational comments about how developers can avoid this issue
8. Ensure proper error handling for all calls
9. Always check for sufficient funds before making ETH transfers

Remember this is for educational and defensive purposes only. The goal is to help developers understand vulnerabilities so they can write more secure code.

Return only the complete Solidity code with no additional explanations.
"""

        # Create appropriate messages based on model type
        if self.model_config.supports_reasoning(self.model_name):
            messages = [
                {"role": "system", "content": "You are a smart contract security educator creating educational PoC tests."},
                {"role": "user", "content": prompt}
            ]
        else:
            messages = [
                {"role": "user", "content": prompt}
            ]

        # Import token tracker
        from utils.token_tracker import token_tracker
        
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
                agent_name="generator",
                model_name=self.model_name,
                prompt_tokens=resp.usage.prompt_tokens,
                completion_tokens=resp.usage.completion_tokens,
                total_tokens=resp.usage.total_tokens
            )

        # Extract the code from the response
        response_text = resp.choices[0].message.content

        # Ensure we have a valid contract by doing some basic checks
        if "contract" not in response_text or "function test" not in response_text:
            # Fallback to a basic template if the AI didn't generate valid code
            return self._generate_basic_template(vulnerability_info, exploit_plan)

        return response_text

    def save_poc_locally(self, poc_code: str, vuln_type: str) -> str:
        """
        Save the generated PoC contract to a file

        Args:
            poc_code: The Solidity code
            vuln_type: Type of vulnerability

        Returns:
            The filename where the code was saved
        """
        # Create exploit directory if it doesn't exist
        os.makedirs("exploit", exist_ok=True)

        ts = int(time.time())
        filename = f"exploit/src/test/PoC_{vuln_type}_{ts}.sol"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(poc_code)

        print_success(f"PoC saved to {filename}")
        return filename

    def _extract_relevant_functions(self, vulnerability_info: Dict) -> List[str]:
        """
        Extract relevant function names from vulnerability info
        """
        functions = vulnerability_info.get("affected_functions", [])
        return [fn.split(".")[-1] if "." in fn else fn for fn in functions]

    def _parse_steps(self, steps: List[str]) -> str:
        """
        Parse steps from exploit plan and format them
        """
        if not steps:
            return "No specific steps provided"

        formatted_steps = []
        for i, step in enumerate(steps, 1):
            formatted_steps.append(f"{i}. {step}")

        return "\n".join(formatted_steps)

    def _generate_basic_template(self, vulnerability_info: Dict, exploit_plan: Dict) -> str:
        """
        Generate a basic template as a fallback
        """
        vuln_type = vulnerability_info.get("vulnerability_type", "unknown").capitalize()
        affected_functions = self._extract_relevant_functions(vulnerability_info)

        return f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "./BaseTestWithBalanceLog.sol";

// @KeyInfo - Vulnerability: {vuln_type}
// Affected Functions: {', '.join(affected_functions)}
// This test demonstrates the vulnerability found in the analyzed contract for educational purposes only

contract {vuln_type}ExploitTest is BaseTestWithBalanceLog {{
    // For forking Ethereum mainnet
    uint256 blockNumber = 18000000; // Recent Ethereum block

    function setUp() public {{
        // Setup the fork
        vm.createSelectFork("mainnet", blockNumber);

        // Fund testing account with plenty of ETH for operations
        vm.deal(address(this), 100 ether);

        // Deploy any needed contracts for the demonstration
        // TODO: Implement setup based on vulnerability type
    }}

    function testExploit() public balanceLog {{
        console.log("Starting {vuln_type} vulnerability demonstration");

        // EDUCATIONAL NOTE: This test demonstrates how the {vuln_type} vulnerability can manifest
        // in smart contracts and how developers can protect against it.

        // TODO: Implement the exploit based on the plan
        // Setup steps:
        // {self._parse_steps(exploit_plan.get("setup_steps", []))}

        // Execution steps:
        // {self._parse_steps(exploit_plan.get("execution_steps", []))}

        // SECURITY BEST PRACTICE: Always handle errors from external calls and check return values

        // Validation steps:
        // {self._parse_steps(exploit_plan.get("validation_steps", []))}

        // MITIGATION STRATEGIES:
        // 1. Always follow the checks-effects-interactions pattern
        // 2. Use OpenZeppelin's security tools and libraries
        // 3. Get multiple professional audits before deploying important contracts
    }}
}}
"""

    def generate_basetest_file(self) -> str:
        """
        Generate the BaseTestWithBalanceLog.sol file needed for the PoC to work
        """
        os.makedirs("exploit", exist_ok=True)

        basetest_content = """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "forge-std/Test.sol";

contract BaseTestWithBalanceLog is Test {
    // Change this to the target token to get token balance of
    // Keep it address 0 if its ETH that is gotten at the end of the exploit
    address fundingToken = address(0);

    struct ChainInfo {
        string name;
        string symbol;
    }

    mapping(uint256 => ChainInfo) private chainIdToInfo;

    constructor() {
        chainIdToInfo[1] = ChainInfo("MAINNET", "ETH");
        chainIdToInfo[238] = ChainInfo("BLAST", "ETH");
        chainIdToInfo[10] = ChainInfo("OPTIMISM", "ETH");
        chainIdToInfo[250] = ChainInfo("FANTOM", "FTM");
        chainIdToInfo[42_161] = ChainInfo("ARBITRUM", "ETH");
        chainIdToInfo[56] = ChainInfo("BSC", "BNB");
        chainIdToInfo[1285] = ChainInfo("MOONRIVER", "MOVR");
        chainIdToInfo[100] = ChainInfo("GNOSIS", "XDAI");
        chainIdToInfo[43_114] = ChainInfo("AVALANCHE", "AVAX");
        chainIdToInfo[137] = ChainInfo("POLYGON", "MATIC");
        chainIdToInfo[42_220] = ChainInfo("CELO", "CELO");
        chainIdToInfo[8453] = ChainInfo("BASE", "ETH");
    }

    function getChainInfo(
        uint256 chainId
    ) internal view returns (string memory, string memory) {
        ChainInfo storage info = chainIdToInfo[chainId];
        return (info.name, info.symbol);
    }

    function getChainSymbol(
        uint256 chainId
    ) internal view returns (string memory symbol) {
        (, symbol) = getChainInfo(chainId);
        // Return ETH as default if chainID is not registered in mapping
        if (bytes(symbol).length == 0) {
            symbol = "ETH";
        }
    }

    function getFundingBal() internal returns (uint256) {
        return fundingToken == address(0)
            ? address(this).balance
            : TokenHelper.getTokenBalance(fundingToken, address(this));
    }

    function getFundingDecimals() internal returns (uint8) {
        return fundingToken == address(0) ? 18 : TokenHelper.getTokenDecimals(fundingToken);
    }

    function getBaseCurrencySymbol() internal returns (string memory) {
        string memory chainSymbol = getChainSymbol(block.chainid);
        return fundingToken == address(0) ? chainSymbol : TokenHelper.getTokenSymbol(fundingToken);
    }

    modifier balanceLog() {
        // Ensure test contract has some initial ETH (enough to run tests)
        if (fundingToken == address(0)) {
            // Deal 0 ETH for logging initial balance, but keep existing ETH
            uint256 existingBalance = address(this).balance;
            vm.deal(address(this), 0);
            logBalance("Before");
            // Restore original balance plus some extra for test operations
            vm.deal(address(this), existingBalance + 10 ether);
        } else {
            logBalance("Before");
        }

        _;

        logBalance("After");
    }

    function logBalance(
        string memory stage
    ) private {
        emit log_named_decimal_uint(
            string(abi.encodePacked("Attacker ", getBaseCurrencySymbol(), " Balance ", stage, " exploit")),
            getFundingBal(),
            getFundingDecimals()
        );
    }
}

library TokenHelper {
    function callTokenFunction(
        address tokenAddress,
        bytes memory data,
        bool staticCall
    ) private returns (bytes memory) {
        (bool success, bytes memory result) = staticCall ? tokenAddress.staticcall(data) : tokenAddress.call(data);
        require(success, "Failed to call token function");
        return result;
    }

    function getTokenBalance(address tokenAddress, address targetAddress) internal returns (uint256) {
        bytes memory result =
            callTokenFunction(tokenAddress, abi.encodeWithSignature("balanceOf(address)", targetAddress), true);
        return abi.decode(result, (uint256));
    }

    function getTokenDecimals(
        address tokenAddress
    ) internal returns (uint8) {
        bytes memory result = callTokenFunction(tokenAddress, abi.encodeWithSignature("decimals()"), true);
        return abi.decode(result, (uint8));
    }

    function getTokenSymbol(
        address tokenAddress
    ) internal returns (string memory) {
        bytes memory result = callTokenFunction(tokenAddress, abi.encodeWithSignature("symbol()"), true);
        return abi.decode(result, (string));
    }

    function approveToken(address token, address spender, uint256 spendAmount) internal returns (bool) {
        bytes memory result =
            callTokenFunction(token, abi.encodeWithSignature("approve(address,uint256)", spender, spendAmount), false);
        return abi.decode(result, (bool));
    }

    function transferToken(address token, address receiver, uint256 amount) internal returns (bool) {
        bytes memory result =
            callTokenFunction(token, abi.encodeWithSignature("transfer(address,uint256)", receiver, amount), false);
        return abi.decode(result, (bool));
    }
}
"""

        filename = "exploit/src/test/basetest.sol"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(basetest_content)

        return filename
