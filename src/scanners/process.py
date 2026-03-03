import psutil
from typing import Dict, Any
from scanners.base import SystemScanner

class ProcessScanner(SystemScanner):
    @property
    def scanner_name(self) -> str:
        return "process_info"

    def scan(self) -> Dict[str, Any]:
        suspicious_found = []
        running_processes = []
        process_count = 0

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                p_info = proc.info
                if p_info['name']:
                    process_count += 1
                    
                    # 1. 전체 프로세스 목록에 추가 (대시보드 표시용)
                    running_processes.append({
                        "pid": p_info['pid'], 
                        "name": p_info['name']
                    })
                    
                    # 2. 의심스러운 프로세스 검사
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
            "suspicious_processes": suspicious_found,
            "running_processes": running_processes # 결과 딕셔너리에 추가
        }