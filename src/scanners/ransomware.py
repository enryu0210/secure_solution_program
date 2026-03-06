import os
import logging
import ctypes
import time # [추가] 타이밍 제어를 위해 임포트
import psutil
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
        self.suspended_processes = []
        self.safe_process_whitelist = [
            "explorer.exe", "searchindexer.exe", "svchost.exe", 
            "msmpeng.exe", "backup_tool.exe", "code.exe"
        ] 
        
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

    def _find_culprit(self, filepath):
        """해당 파일을 열고 있는 프로세스의 PID를 찾습니다."""
        try:
            filepath = os.path.normpath(filepath)
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    # 윈도우 권한 문제로 open_files() 호출 시 무한정 대기(Hang)가 자주 일어나는 시스템 프로세스들 스킵
                    proc_name = proc.info.get('name', '').lower()
                    if proc_name in ['system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe']:
                        continue
                        
                    username = proc.info.get('username')
                    if username and ('SYSTEM' in username or 'NT AUTHORITY' in username):
                        continue

                    for item in proc.open_files():
                        if os.path.normpath(item.path) == filepath:
                            return proc
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    continue
        except Exception as e:
            logging.error(f"범인 추적 중 오류: {e}")
        return None

    def _emergency_action(self, proc):
        """의심 프로세스를 일시 중지합니다."""
        proc_name = proc.info.get('name', '').lower()
        if proc_name in self.safe_process_whitelist:
            logging.info(f"⚠️ [Safe] 화이트리스트 프로세스 감지: {proc_name} (차단 제외)")
            return

        try:
            proc.suspend() 
            logging.critical(f"🚫 [ACTION] 랜섬웨어 의심 프로세스 '{proc.info['name']}'(PID: {proc.pid})를 일시 중지했습니다!")
            
            # 증거 수집용으로 저장 (중복 저장 방지)
            if not any(p['pid'] == proc.pid for p in self.suspended_processes):
                self.suspended_processes.append({"pid": proc.pid, "name": proc.info['name']})
                
        except Exception as e:
            logging.error(f"일시 중지(Suspend) 실패: {e}")

    def resume_and_whitelist(self, pid_str: str):
        """서버 명령으로 프로세스 일시 정지를 해제하고 화이트리스트에 이름을 추가합니다."""
        try:
            pid = int(pid_str)
            process = psutil.Process(pid)
            process_name = process.name().lower()
            
            # 프로세스 재개 (Resume)
            process.resume()
            
            # 화이트리스트에 없으면 추가
            if process_name not in self.safe_process_whitelist:
                self.safe_process_whitelist.append(process_name)
                
            # 일시 정지 목록에서 제거
            self.suspended_processes = [p for p in self.suspended_processes if p['pid'] != pid]
            
            logging.info(f"✅ [Recover] 오탐지 프로세스 '{process_name}' (PID: {pid}) 재생 및 화이트리스트 추가 완료!")
        except psutil.NoSuchProcess:
            logging.error(f"❌ 복구 실패: PID {pid_str} 프로세스를 찾을 수 없습니다. (이미 종료됨)")
        except Exception as e:
            logging.error(f"❌ 프로세스 재개 및 예외처리(화이트리스트) 중 오류 발생: {e}")

    def scan(self) -> Dict[str, Any]:
        logging.info("🔍 랜섬웨어 허니팟 상태 점검 중...")
        
        current_alerts = self.event_handler.alerts.copy()
        self.event_handler.alerts.clear() 
        
        if current_alerts:
            self.is_compromised = True
            self.all_tampered_files.update(current_alerts)
            
            # 마지막 알림 파일 경로 추출하여 어떤 프로세스인지 추적 시도 (예: "수정(암호화) 시도 감지: C:\...")
            last_alert_path = current_alerts[-1].split(": ")[-1]
            culprit = self._find_culprit(last_alert_path)
            if culprit:
                self._emergency_action(culprit)
            
        status = "CRITICAL: Ransomware Activity Detected!" if self.is_compromised else "Safe"
            
        return {
            "status": status,
            "tampered_files": list(self.all_tampered_files),
            "suspended_processes": self.suspended_processes,
            "error": None
        }

    def reset_status(self):
        logging.info("🔄 서버 명령 수신: 랜섬웨어 경고 상태를 초기화하고 미끼 파일을 복구합니다.")
        self.is_compromised = False
        self.all_tampered_files.clear()
        self.event_handler.alerts.clear()
        self.suspended_processes.clear()
        self._setup_honeypot()