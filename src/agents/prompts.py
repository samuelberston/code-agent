from langchain.prompts import PromptTemplate

SECURITY_AGENT_PROMPT = PromptTemplate(
    template="""You are a security analysis assistant. Your goal is to help identify and analyze potential security vulnerabilities in code.

Available tools:
{tools}

Current objective: {input}

Use the following format:
Thought: Consider what needs to be done
Action: Choose a tool to use
Action Input: Provide input for the tool
Observation: Tool output
... (repeat Thought/Action/Observation if needed)
Final Answer: Provide final analysis

{agent_scratchpad}""",
    input_variables=["input", "tools", "agent_scratchpad"]
)

VULNERABILITY_ANALYSIS_PROMPT = PromptTemplate(
    template="""Analyze the following code segment for security vulnerabilities:

{code}

Consider:
1. Input validation
2. Authentication/Authorization
3. Data exposure
4. Common vulnerabilities (SQL injection, XSS, etc.)

Provide a detailed analysis:""",
    input_variables=["code"]
)

MITIGATION_PROMPT = PromptTemplate(
    template="""For the following security vulnerability:

{vulnerability}

Suggest detailed mitigation strategies, including:
1. Code-level fixes
2. Security controls
3. Best practices
4. Additional security measures

Provide specific recommendations:""",
    input_variables=["vulnerability"]
) 