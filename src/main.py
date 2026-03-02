import os
import sys
import ctypes
import logging
import socket
import json
import requests

# 임포트 에러 방지를 위한 경로 주입
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from config_loader import load_config
from agent_manager import AgentManager
from scanners.process import ProcessScanner
from scanners.network import NetworkScanner
from scanners.event_log import EventLogScanner

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_machine_id():
    """현재 PC의 고유 식별자(컴퓨터 이름)를 가져옵니다."""
    return socket.gethostname()

def send_to_server(payload_json: str, server_url: str):
    """수집된 JSON 데이터를 FastAPI 백엔드로 POST 전송합니다."""
    headers = {'Content-Type': 'application/json'}
    try:
        # 1. 기존 payload(문자열)를 딕셔너리로 변환
        data = json.loads(payload_json)
        
        # 2. 서버가 요구하는 machine_id를 데이터 최상단에 주입
        data['machine_id'] = get_machine_id()
        
        logging.info(f"🚀 중앙 서버({server_url})로 보안 데이터 전송 중...")
        
        # 3. POST 요청으로 데이터 전송 (타임아웃 10초 설정)
        response = requests.post(server_url, json=data, headers=headers, timeout=10)
        
        if response.status_code == 200:
            logging.info("✅ 서버 전송 성공!")
            print(f"[서버 응답] {response.json()}")
        else:
            logging.error(f"❌ 서버 전송 실패 (상태 코드: {response.status_code})")
            print(f"[서버 에러 내용] {response.text}")
            
    except requests.exceptions.ConnectionError:
        logging.error("❌ 서버에 연결할 수 없습니다. FastAPI 서버가 켜져 있는지 확인하세요.")
    except Exception as e:
        logging.error(f"❌ 전송 중 오류 발생: {e}")

def main():
    if not is_admin():
        print("[System] 관리자 권한이 필요합니다. UAC 창을 통해 권한을 승인해 주세요.")
        
        script_path = os.path.abspath(sys.argv[0])
        
        # =====================================================================
        # [최종 해결책] 
        # 파이썬을 직접 실행하는 대신 cmd.exe를 띄우고, 
        # "파이썬 실행 & 끝나면 무조건 pause"라는 명령어를 통째로 던집니다.
        # 이렇게 하면 파이썬이 종료되거나 에러가 나더라도 cmd 창은 절대 닫히지 않습니다.
        # =====================================================================
        params = f'/c ""{sys.executable}" "{script_path}" & pause"'
        
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", "cmd.exe", params, None, 1
        )
        # 원본(일반 권한) 스크립트는 즉시 종료합니다.
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
        
        final_payload = manager.run_all_scans()
        print("\n========================================")
        print("[서버 전송 대기 중인 JSON Payload]")
        print(final_payload)
        print("========================================\n")

        # 백엔드 서버로 데이터 전송 실행
        # 로컬 테스트용 주소 (포트 번호가 FastAPI 설정과 일치해야 합니다)
        SERVER_URL = "http://localhost:8000/api/v1/report"
        send_to_server(final_payload, SERVER_URL)

    except Exception as e:
        print(f"\n[오류 발생] {e}")
        import traceback
        traceback.print_exc()
        
    # finally 구문을 완전히 삭제했습니다. 
    # 창 유지는 위에서 설정한 cmd.exe의 '& pause'가 알아서 처리합니다.

if __name__ == "__main__":
    main()