import os
import sys
import ctypes
import logging
import time
import socket
import json
import requests
import threading

# 임포트 에러 방지를 위한 경로 주입
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from config_loader import load_config
from agent_manager import AgentManager
from scanners.process import ProcessScanner
from scanners.network import NetworkScanner
from scanners.event_log import EventLogScanner
from scanners.software import SoftwareScanner
from scanners.ransomware import RansomwareScanner
from scanners.usb import UsbScanner
from command_executor import CommandExecutor

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_machine_id():
    """현재 PC의 고유 식별자(컴퓨터 이름)를 가져옵니다."""
    return socket.gethostname()

def send_to_server(payload_json: str, server_url: str, ransomware_scanner, executor): # executor 파라미터 추가
    headers = {'Content-Type': 'application/json'}
    try:
        data = json.loads(payload_json)
        data['machine_id'] = get_machine_id()
        
        # 서버로 데이터 전송
        response = requests.post(server_url, json=data, headers=headers, timeout=10)
        
        if response.status_code == 200:
            logging.info("✅ 서버 전송 성공!")
            
            response_data = response.json()
            commands = response_data.get("commands", [])
            
            # 수신된 명령 리스트를 순회하며 모듈화된 처리 진행
            for cmd in commands:
                # cmd가 단순 문자열 명령일 때
                if cmd == "reset_ransomware":
                    ransomware_scanner.reset_status()
                # cmd가 C&C 딕셔너리 명령일 때 (예: {"action": "kill_process", ...})
                elif isinstance(cmd, dict):
                    if cmd.get("action") == "resume_and_whitelist":
                        ransomware_scanner.resume_and_whitelist(cmd.get("target"))
                    else:
                        executor.execute(cmd)
                else:
                    logging.warning(f"알 수 없는 명령 형태입니다: {cmd}")
                    
        else:
            logging.error(f"❌ 서버 전송 실패 (상태 코드: {response.status_code})")
            
    except Exception as e:
        logging.error(f"❌ 전송 중 오류 발생: {e}")

def realtime_worker(machine_id: str, base_url: str, config, ransomware_scanner, executor):
    """3초마다 프로세스 목록을 수집하여 서버로 전송하고, 동시에 C&C 명령을 수신합니다."""
    realtime_url = f"{base_url}/agent/{machine_id}/realtime"
    
    # 실시간 수집을 위한 독립적인 스캐너 인스턴스 생성
    process_scanner = ProcessScanner(config)
    
    while True:
        try:
            # 1. 가볍고 빠른 프로세스 스캔
            p_data = process_scanner.scan()
            
            # 2. 서버로 POST 전송 (프로세스 데이터 + 하트비트 동시 처리)
            payload = {"process_info": p_data}
            response = requests.post(realtime_url, json=payload, timeout=5)
            
            if response.status_code == 200:
                commands = response.json().get("commands", [])
                
                for cmd in commands:
                    if cmd == "reset_ransomware":
                        logging.info("🔄 [Realtime] 랜섬웨어 초기화 명령 수신")
                        ransomware_scanner.reset_status()
                    elif isinstance(cmd, dict):
                        logging.info(f"⚡ [Realtime] 원격 제어 명령 수신: {cmd.get('action')}")
                        if cmd.get("action") == "resume_and_whitelist":
                            ransomware_scanner.resume_and_whitelist(cmd.get("target"))
                        else:
                            executor.execute(cmd)
                        
        except Exception:
            # 실시간 통신은 에러가 나도 조용히 넘기고 3초 뒤 다시 시도
            pass
            
        time.sleep(3) # 3초 주기

def main():
    if not is_admin():
        print("[System] 관리자 권한이 필요합니다. UAC 창을 통해 권한을 승인해 주세요.")
        script_path = os.path.abspath(sys.argv[0])
        params = f'/c ""{sys.executable}" "{script_path}" & pause"'
        
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", "cmd.exe", params, None, 1
        )
        sys.exit()

    # --- 여기서부터는 관리자 권한 창에서 실행되는 로직 ---
    try:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
        
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_dir, "assets", "config.json")
        
        agent_config = load_config(config_path)
        manager = AgentManager(agent_config)
        
        manager.register_scanner(ProcessScanner(agent_config))
        manager.register_scanner(NetworkScanner(agent_config))
        manager.register_scanner(EventLogScanner(agent_config))
        manager.register_scanner(SoftwareScanner(agent_config))
        manager.register_scanner(UsbScanner(agent_config))
    
        # C&C 명령 실행기 인스턴스 생성
        executor = CommandExecutor()
        
        # 랜섬웨어 스캐너만 따로 빼서 변수에 저장한 뒤 등록합니다.
        ransom_scanner = RansomwareScanner(agent_config)
        manager.register_scanner(ransom_scanner)
        
        SERVER_URL = "http://localhost:28080/api/v1/report"
        API_BASE_URL = SERVER_URL.rsplit('/', 1)[0]
        SCAN_INTERVAL = 60 # 하드코딩 방지: 대기 시간을 변수로 분리하여 일치시킴
        
        logging.info("🛡️ 에이전트가 실시간 감시 모드로 전환되었습니다.")
        logging.info("⚠️ 종료하려면 이 까만 콘솔 창을 그냥 닫으시면 됩니다.\n")

        # 메인 무거운 스캔과 별개로, 3초마다 명령만 확인하는 백그라운드 스레드 가동
        machine_id = get_machine_id()
        rt_thread = threading.Thread(
            target=realtime_worker, 
            args=(machine_id, API_BASE_URL, agent_config, ransom_scanner, executor),
            daemon=True
        )
        rt_thread.start()
        logging.info("🚀 실시간 프로세스 감시 및 C&C 스레드가 시작되었습니다. (3초 주기)")

        while True:
            final_payload = manager.run_all_scans()
            
            # 서버로 데이터 전송 실행 (executor 파라미터 추가)
            send_to_server(final_payload, SERVER_URL, ransom_scanner, executor)
            
            logging.info(f"⏳ 다음 보안 스캔까지 {SCAN_INTERVAL}초 대기 중...\n")
            time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:
        logging.info("\n🛑 사용자에 의해 에이전트 실시간 감시가 종료되었습니다.")
    except Exception as e:
        print(f"\n[오류 발생] {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()