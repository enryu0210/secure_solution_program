import psutil
import logging
from typing import Dict, Any, Union

class CommandExecutor:
    """
    서버로부터 수신한 C&C(명령 및 제어) 명령을 안전하게 실행하는 모듈입니다.
    """
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def execute(self, command: Union[str, Dict[str, Any]]) -> bool:
        # 1. 랜섬웨어 초기화 같은 단순 문자열 명령 처리
        if isinstance(command, str):
            if command == "reset_ransomware":
                self.logger.info("명령 수신: 랜섬웨어 허니팟 상태를 초기화합니다.")
                # (이 부분은 main 루프나 AgentManager에서 RansomwareScanner.reset_status()를 호출하도록 연계)
                return True
            return False

        # 2. 딕셔너리 형태의 C&C 명령 처리 (예: 프로세스 종료)
        action = command.get("action")
        target = command.get("target")

        if not action:
            return False

        self.logger.info(f"C&C 명령 수신: {action} (대상: {target})")

        if action == "kill_process":
            return self._kill_process(target)
        else:
            self.logger.warning(f"알 수 없는 명령입니다: {action}")
            return False

    def _kill_process(self, pid_str: str) -> bool:
        """지정된 PID의 프로세스를 강제 종료합니다."""
        try:
            pid = int(pid_str.strip())
            process = psutil.Process(pid)
            
            # 프로세스 종료 시도
            process.terminate()
            process.wait(timeout=3) # 종료될 때까지 최대 3초 대기
            
            self.logger.info(f"✅ 프로세스(PID: {pid})가 성공적으로 종료되었습니다.")
            return True
            
        except ValueError:
            self.logger.error("❌ 유효하지 않은 PID 형식입니다. (숫자만 입력해야 합니다)")
        except psutil.NoSuchProcess:
            self.logger.error(f"❌ PID {pid_str}에 해당하는 프로세스를 찾을 수 없습니다. (이미 종료되었을 수 있습니다)")
        except psutil.AccessDenied:
            self.logger.error(f"❌ PID {pid_str} 프로세스를 종료할 권한이 없습니다. (에이전트를 관리자 권한으로 실행했는지 확인하세요)")
        except Exception as e:
            self.logger.error(f"❌ 프로세스 종료 중 알 수 없는 오류 발생: {e}")
            
        return False