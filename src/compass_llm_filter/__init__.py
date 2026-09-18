"""compass-llm-filter — двустороннее маскирование PII для LLM."""

from compass_llm_filter.core.anonymizer import Anonymizer
from compass_llm_filter.core.injection import detect_prompt_injection

__version__ = "0.1.0"
__all__ = ["Anonymizer", "detect_prompt_injection", "__version__"]
