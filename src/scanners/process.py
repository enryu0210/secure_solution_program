import psutil
from typing import Dict, Any
from scanners.base import SystemScanner

class ProcessScanner(SystemScanner):
    @property
    def scanner_name(self) -> str:
        return "process_info"

    def scan(self) -> Dict[str, Any]:
        self.logger.info("활성 프로세스 스캔 시작...")
        suspicious_found = []
        process_count = 0

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                p_info = proc.info
                process_count += 1
                
                # config.json의 값을 기반으로 검사
                if p_info['name']:
                    is_suspicious = any(
                        sus_name.lower() in p_info['name'].lower() 
                        for sus_name in self.config.suspicious_process_names
                    )
                    if is_suspicious:
                        suspicious_found.append(p_info)
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        return {
            "total_processes": process_count,
            "suspicious_processes": suspicious_found
        }