import os
import logging
import ctypes
import time # [추가] 타이밍 제어를 위해 임포트
from typing import Dict, Any
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scanners.base import SystemScanner

class HoneypotEventHandler(FileSystemEventHandler):
    def __init__(self):
        self.alerts = []
        self.ignore_events = False # [추가] 내가 파일을 수정할 때는 감시 끄기

    def on_modified(self, event):
        # 감시가 켜져 있을 때만 알림 추가
        if not event.is_directory and not self.ignore_events:
            self.alerts.append(f"수정(암호화) 시도 감지: {event.src_path}")

    def on_deleted(self, event):
        if not event.is_directory and not self.ignore_events:
            self.alerts.append(f"삭제 시도 감지: {event.src_path}")

class RansomwareScanner(SystemScanner):
    def __init__(self, config):
        super().__init__(config)
        self.honeypot_dir = os.path.join(os.environ.get('PUBLIC', 'C:\\Users\\Public'), "Documents", "SystemBackup_DoNotModify")
        self.event_handler = HoneypotEventHandler()
        self.observer = Observer()
        
        self.is_compromised = False 
        self.all_tampered_files = set() 
        
        self._setup_honeypot()
        self._start_monitoring()

    @property
    def scanner_name(self) -> str:
        return "ransomware_info"

    def _setup_honeypot(self):
        # [추가] 파일 복구 작업 전에 잠시 감시자 눈 가리기
        self.event_handler.ignore_events = True
        
        if not os.path.exists(self.honeypot_dir):
            os.makedirs(self.honeypot_dir)
            
        dummy_files = ["financial_records_2026.xlsx", "employee_passwords.txt", "customer_db_backup.sql"]
        
        for f in dummy_files:
            path = os.path.join(self.honeypot_dir, f)
            if not os.path.exists(path):
                with open(path, "w", encoding="utf-8") as file:
                    file.write("This is a system generated honeypot file. Do not modify.")
                    
        FILE_ATTRIBUTE_HIDDEN = 0x02
        ctypes.windll.kernel32.SetFileAttributesW(self.honeypot_dir, FILE_ATTRIBUTE_HIDDEN)
        
        # [추가] OS가 파일을 다 쓸 때까지 0.5초 대기 후, 쌓인 오탐지 찌꺼기를 지우고 눈 가리개 벗기기
        time.sleep(0.5)
        self.event_handler.alerts.clear() 
        self.event_handler.ignore_events = False

    def _start_monitoring(self):
        self.observer.schedule(self.event_handler, self.honeypot_dir, recursive=False)
        self.observer.start()
        logging.info(f"🛡️ 랜섬웨어 허니팟 감시가 시작되었습니다. (경로: {self.honeypot_dir})")

    def scan(self) -> Dict[str, Any]:
        logging.info("🔍 랜섬웨어 허니팟 상태 점검 중...")
        
        current_alerts = self.event_handler.alerts.copy()
        self.event_handler.alerts.clear() 
        
        if current_alerts:
            self.is_compromised = True
            self.all_tampered_files.update(current_alerts)
            
        status = "CRITICAL: Ransomware Activity Detected!" if self.is_compromised else "Safe"
            
        return {
            "status": status,
            "tampered_files": list(self.all_tampered_files),
            "error": None
        }

    def reset_status(self):
        logging.info("🔄 서버 명령 수신: 랜섬웨어 경고 상태를 초기화하고 미끼 파일을 복구합니다.")
        self.is_compromised = False
        self.all_tampered_files.clear()
        self.event_handler.alerts.clear()
        self._setup_honeypot()