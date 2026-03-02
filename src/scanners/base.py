import logging
from abc import ABC, abstractmethod
from typing import Dict, Any
from config_loader import AgentConfig

class SystemScanner(ABC):
    def __init__(self, config: AgentConfig):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def scan(self) -> Dict[str, Any]:
        """수집한 데이터를 딕셔너리 형태로 반환"""
        pass

    @property
    @abstractmethod
    def scanner_name(self) -> str:
        """결과 JSON에 사용될 Key 이름"""
        pass