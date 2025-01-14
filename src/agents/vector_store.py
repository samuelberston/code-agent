from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import Chroma
from langchain.text_splitter import PythonCodeTextSplitter
from typing import List

class CodebaseVectorStore:
    def __init__(self, api_key: str):
        self.embeddings = OpenAIEmbeddings(openai_api_key=api_key)
        self.vector_store = None

    def initialize(self, source_files: List[str]):
        code_splitter = PythonCodeTextSplitter(
            chunk_size=1000,
            chunk_overlap=100
        )
        
        documents = []
        for file_path in source_files:
            with open(file_path) as f:
                code = f.read()
                chunks = code_splitter.split_text(code)
                documents.extend([
                    {"content": chunk, "source": file_path}
                    for chunk in chunks
                ])
        
        self.vector_store = Chroma.from_documents(
            documents,
            self.embeddings,
            collection_name="security_codebase"
        )

    def search(self, query: str) -> str:
        """Search the codebase using vector similarity"""
        if not self.vector_store:
            return "Vector store not initialized"
            
        results = self.vector_store.similarity_search(query, k=3)
        return "\n\n".join(f"From {doc.metadata['source']}:\n{doc.page_content}" 
                          for doc in results) 