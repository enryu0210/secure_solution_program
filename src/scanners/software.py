import winreg
import logging
from typing import Dict, Any, List

from scanners.base import SystemScanner

class SoftwareScanner(SystemScanner):
    def __init__(self, config):
        # 부모 클래스가 config만 받도록 설계되었을 테니 그대로 전달합니다.
        super().__init__(config)

    # ==========================================
    # [핵심 수정 부분] 추상 메서드(이름표) 강제 구현
    # ==========================================
    @property
    def scanner_name(self) -> str:
        return "software_info"
    # ==========================================

    def scan(self) -> Dict[str, Any]:
        logging.info("🔍 설치된 소프트웨어 및 버전 스캔 시작...")
        installed_software = []
        
        # 윈도우 레지스트리 경로 (64비트 및 32비트 프로그램 모두 탐색)
        registry_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ]
        
        for path in registry_paths:
            try:
                reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                for i in range(0, winreg.QueryInfoKey(reg_key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(reg_key, i)
                        subkey = winreg.OpenKey(reg_key, subkey_name)
                        
                        display_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                        
                        try:
                            display_version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                        except FileNotFoundError:
                            display_version = "Unknown"
                            
                        if display_name:
                            installed_software.append({
                                "name": display_name,
                                "version": display_version
                            })
                    except OSError:
                        continue
            except OSError as e:
                logging.error(f"레지스트리 접근 오류 ({path}): {e}")
                
        return {
            "total_installed": len(installed_software),
            "software_list": installed_software,
            "error": None
        }