from abc import ABC, abstractmethod
import ast
from ..models.security_context import SecurityContext

class BaseAnalyzer(ABC):
    def __init__(self, context: SecurityContext):
        self.context = context

    @abstractmethod
    def analyze(self, tree: ast.AST) -> None:
        pass 