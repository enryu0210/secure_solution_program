import os
import sys
import ctypes
import logging
import time
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
from scanners.software import SoftwareScanner
from scanners.ransomware import RansomwareScanner

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_machine_id():
    """현재 PC의 고유 식별자(컴퓨터 이름)를 가져옵니다."""
    return socket.gethostname()

def send_to_server(payload_json: str, server_url: str, ransomware_scanner):
    headers = {'Content-Type': 'application/json'}
    try:
        data = json.loads(payload_json)
        data['machine_id'] = get_machine_id()
        
        # 서버로 데이터 전송
        response = requests.post(server_url, json=data, headers=headers, timeout=10)
        
        if response.status_code == 200:
            logging.info("✅ 서버 전송 성공!")
            
            # 서버가 응답과 함께 내려보낸 '명령(command)' 확인
            resp_data = response.json()
            commands = resp_data.get("commands", [])
            
            # 초기화 명령이 들어있다면 스캐너 상태 리셋
            if "reset_ransomware" in commands:
                ransomware_scanner.reset_status()
                
        else:
            logging.error(f"❌ 서버 전송 실패 (상태 코드: {response.status_code})")
            
    except Exception as e:
        logging.error(f"❌ 전송 중 오류 발생: {e}")

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
        
        # 랜섬웨어 스캐너만 따로 빼서 변수에 저장한 뒤 등록합니다.
        ransom_scanner = RansomwareScanner(agent_config)
        manager.register_scanner(ransom_scanner)
        
        SERVER_URL = "http://localhost:8000/api/v1/report"
        
        logging.info("🛡️ 에이전트가 실시간 감시 모드로 전환되었습니다.")
        logging.info("⚠️ 종료하려면 이 까만 콘솔 창을 그냥 닫으시면 됩니다.\n")

        # =====================================================================
        # [추가된 부분] 무한 루프를 돌면서 30초마다 스캔 및 서버 전송
        # =====================================================================
        while True:
            final_payload = manager.run_all_scans()
            
            # 서버로 데이터 전송 실행
            send_to_server(final_payload, SERVER_URL, ransom_scanner)
            
            logging.info("⏳ 다음 보안 스캔까지 30초 대기 중...\n")
            time.sleep(30) # 30초 동안 대기 후 다시 루프의 처음으로 돌아감

    except KeyboardInterrupt:
        logging.info("\n🛑 사용자에 의해 에이전트 실시간 감시가 종료되었습니다.")
    except Exception as e:
        print(f"\n[오류 발생] {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()