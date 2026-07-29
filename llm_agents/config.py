from typing import Dict, Optional, Tuple
from dotenv import load_dotenv

# Agents are also used by the Flask application and utility scripts, not only
# through main.py.  Load the project environment at the shared configuration
# boundary so those supported entry points receive the same Ollama settings.
load_dotenv()

class ModelConfig:
    """
    Configuration class for managing models and API settings across all agents.
    """

    def __init__(
        self,
        analyzer_model: str = "qwen2.5-coder:7b",
        skeptic_model: str = "qwen2.5-coder:7b",
        exploiter_model: str = "qwen2.5-coder:7b",
        generator_model: str = "qwen2.5-coder:7b",
        context_model: str = "qwen2.5-coder:7b",
        base_url: Optional[str] = None,
        skip_poc_generation: bool = False,
        export_markdown: bool = False,
        poc_generation_attempts: int = 3,
        poc_max_retries: int = 3,
        forge_build_timeout: int = 120,
        forge_test_timeout: int = 180,
    ):
        self.analyzer_model = "qwen2.5-coder:7b" if analyzer_model == "ollama" else analyzer_model
        self.skeptic_model = "qwen2.5-coder:7b" if skeptic_model == "ollama" else skeptic_model
        self.exploiter_model = "qwen2.5-coder:7b" if exploiter_model == "ollama" else exploiter_model
        self.generator_model = "qwen2.5-coder:7b" if generator_model == "ollama" else generator_model
        self.context_model = "qwen2.5-coder:7b" if context_model == "ollama" else context_model
        self.base_url = base_url
        self.skip_poc_generation = skip_poc_generation
        self.export_markdown = export_markdown
        self.poc_generation_attempts = max(1, poc_generation_attempts)
        self.poc_max_retries = max(0, poc_max_retries)
        self.forge_build_timeout = max(1, forge_build_timeout)
        self.forge_test_timeout = max(1, forge_test_timeout)

        self.is_reasoning_model = {
            "qwen2.5-coder:7b": False,

            # OpenAI
            "o1-mini": True,
            "o3-mini": True,
            "gpt-4o": False,

            # Anthropic
            "claude-3-5-haiku-latest": False,
            "claude-3-7-sonnet-latest": False,

            # DeepSeek
            "deepseek-chat": False,
            "deepseek-reasoner": True,
        }

        self.model_provider = {
            "qwen2.5-coder:7b": "openai",

            # OpenAI
            "o1-mini": "openai",
            "o3-mini": "openai",
            "gpt-4o": "openai",

            # Anthropic
            "claude-3-5-haiku-latest": "anthropic",
            "claude-3-7-sonnet-latest": "anthropic",

            # DeepSeek
            "deepseek-chat": "deepseek",
            "deepseek-reasoner": "deepseek",
        }

        self.provider_urls = {
            "openai": "http://localhost:11434/v1",
            "anthropic": "https://api.anthropic.com/v1/",
            "deepseek": "https://api.deepseek.com",
        }

    def get_model(self, agent_type: str) -> str:
        if agent_type == "analyzer":
            return self.analyzer_model
        elif agent_type == "skeptic":
            return self.skeptic_model
        elif agent_type == "exploiter":
            return self.exploiter_model
        elif agent_type == "generator":
            return self.generator_model
        elif agent_type == "context":
            return self.context_model
        return self.analyzer_model

    def supports_reasoning(self, model_name: str) -> bool:
        return self.is_reasoning_model.get(model_name, False)

    def get_provider_info(self, model_name: str) -> Tuple[str, str, str]:
        provider = self.model_provider.get(model_name, "openai")

        if provider == "anthropic":
            api_key_env = "ANTHROPIC_API_KEY"
        elif provider == "deepseek":
            api_key_env = "DEEPSEEK_API_KEY"
        else:
            api_key_env = "OPENAI_API_KEY"

        base_url = self.base_url if self.base_url else self.provider_urls.get(provider)

        return provider, api_key_env, base_url

    def get_openai_args(self, model_name: str = None) -> Dict:
        args = {}

        if model_name:
            _, _, provider_base_url = self.get_provider_info(model_name)
            if provider_base_url:
                args["base_url"] = provider_base_url
        elif self.base_url:
            args["base_url"] = self.base_url

        return args
