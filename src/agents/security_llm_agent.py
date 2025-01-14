from langchain.agents import AgentExecutor, create_react_agent
from langchain.chat_models import ChatOpenAI
from typing import Dict

from .tools import create_security_tools
from .prompts import SECURITY_AGENT_PROMPT
from .vector_store import CodebaseVectorStore

class SecurityLLMAgent:
    def __init__(self, api_key: str):
        self.llm = ChatOpenAI(
            temperature=0,
            model="gpt-4",
            openai_api_key=api_key
        )
        self.vector_store = CodebaseVectorStore(api_key)
        self.tools = create_security_tools(self.llm, self.vector_store)

    def initialize_vector_store(self, source_files):
        self.vector_store.initialize(source_files)

    def _create_agent(self):
        agent = create_react_agent(
            llm=self.llm,
            tools=self.tools,
            prompt=SECURITY_AGENT_PROMPT
        )
        
        return AgentExecutor.from_agent_and_tools(
            agent=agent,
            tools=self.tools,
            verbose=True
        )

    def analyze_security(self, context: Dict) -> Dict:
        """Perform comprehensive security analysis"""
        agent = self._create_agent()
        
        analysis = agent.run(
            f"""Analyze the following security context for vulnerabilities:
            Trust Boundaries: {context.get('trust_boundaries')}
            Sensitive Data: {context.get('sensitive_data')}
            Authentication Points: {context.get('authentication_points')}
            
            Provide a detailed security analysis with:
            1. Identified vulnerabilities
            2. Risk assessment
            3. Recommended mitigations"""
        )
        
        return {
            "analysis": analysis,
            "source_references": self._search_codebase(analysis)
        } 