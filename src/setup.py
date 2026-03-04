import os
import sys
import winreg
import ctypes

def is_admin():
    """관리자 권한 확인"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def register_startup():
    """윈도우 레지스트리에 에이전트를 백그라운드 시작 프로그램으로 등록합니다."""
    
    # 1. 일반 python.exe 대신 콘솔 창이 안 뜨는 pythonw.exe를 사용
    python_dir = os.path.dirname(sys.executable)
    pythonw_path = os.path.join(python_dir, 'pythonw.exe')
    
    # 2. 실행할 에이전트 메인 스크립트 경로 (절대 경로로 변환)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    agent_path = os.path.join(base_dir, "src", "main.py")

    # 3. 레지스트리에 등록할 명령어 조합
    # 띄어쓰기가 포함된 경로를 대비해 앞뒤로 쌍따옴표(")를 감싸줍니다.
    command = f'"{pythonw_path}" "{agent_path}"'

    # 4. 등록할 레지스트리 경로 (모든 사용자 적용)
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    app_name = "ShieldX_Security_Agent"

    print("설치 준비 중...")
    print(f"적용될 명령어: {command}")

    try:
        # HKEY_LOCAL_MACHINE에 쓰기 권한으로 접근 (관리자 권한 필수)
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, command)
        winreg.CloseKey(key)
        
        print("\n✅ [성공] ShieldX 에이전트가 백그라운드 서비스로 등록되었습니다.")
        print("이제 PC를 켤 때마다 콘솔 창 없이 조용히 보안 감시가 시작됩니다.")
        
    except PermissionError:
        print("\n❌ [실패] 레지스트리 쓰기 권한이 없습니다. (관리자 권한으로 실행했는지 확인하세요)")
    except Exception as e:
        print(f"\n❌ [실패] 알 수 없는 오류 발생: {e}")

if __name__ == "__main__":
    print("========================================")
    print("🛡️ ShieldX 에이전트 시스템 등록 도구")
    print("========================================")
    
    # 관리자 권한이 없으면 UAC(사용자 계정 컨트롤) 창을 띄워 권한 상승 유도
    if not is_admin():
        print("관리자 권한을 요청합니다...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()
        
    register_startup()
    input("\n설치가 완료되었습니다. 엔터 키를 눌러 종료하세요...")