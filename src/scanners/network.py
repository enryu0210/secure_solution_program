import psutil
from typing import Dict, Any
from scanners.base import SystemScanner

class NetworkScanner(SystemScanner):
    @property
    def scanner_name(self) -> str:
        return "network_info"

    def scan(self) -> Dict[str, Any]:
        self.logger.info("네트워크 연결 상태 스캔 시작...")
        open_ports = []
        
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                port = conn.laddr.port
                open_ports.append({"port": port, "pid": conn.pid})
                
        return {
            "monitored_ports_active": [
                p for p in open_ports if p["port"] in self.config.target_ports
            ]
        }