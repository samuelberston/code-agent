from langchain.agents import Tool
from langchain.prompts import PromptTemplate
from typing import List

from .prompts import VULNERABILITY_ANALYSIS_PROMPT, MITIGATION_PROMPT

def create_security_tools(llm, vector_store) -> List[Tool]:
    return [
        Tool(
            name="CodeSearch",
            func=vector_store.search,
            description="Search through the codebase for specific patterns or vulnerabilities"
        ),
        Tool(
            name="VulnerabilityAnalysis",
            func=lambda code: llm.predict(VULNERABILITY_ANALYSIS_PROMPT.format(code=code)),
            description="Analyze potential security vulnerabilities in code segments"
        ),
        Tool(
            name="MitigationSuggestion",
            func=lambda vuln: llm.predict(MITIGATION_PROMPT.format(vulnerability=vuln)),
            description="Suggest security mitigations for identified vulnerabilities"
        )
    ] 