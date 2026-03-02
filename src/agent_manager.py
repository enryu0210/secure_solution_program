import json
import logging
from typing import List
from config_loader import AgentConfig
from scanners.base import SystemScanner

class AgentManager:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.scanners: List[SystemScanner] = []
        self.logger = logging.getLogger(self.__class__.__name__)

    def register_scanner(self, scanner: SystemScanner) -> None:
        self.scanners.append(scanner)

    def run_all_scans(self) -> str:
        self.logger.info("전체 시스템 스캔을 시작합니다.")
        report = {}
        
        for scanner in self.scanners:
            try:
                report[scanner.scanner_name] = scanner.scan()
            except Exception as e:
                self.logger.error(f"{scanner.scanner_name} 오류: {e}")
                report[scanner.scanner_name] = {"error": str(e)}
                
        return json.dumps(report, indent=4, ensure_ascii=False)