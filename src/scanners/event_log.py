import logging
from typing import Dict, Any
from scanners.base import SystemScanner

try:
    import win32evtlog
    import win32security
    import win32api
    import win32con
except ImportError as e:
    print(f"\n🚨 [치명적 경고] pywin32 임포트 실패: {e}\n")
    win32evtlog = None

class EventLogScanner(SystemScanner):
    @property
    def scanner_name(self) -> str:
        return "event_log_info"

    def enable_security_privilege(self):
        """현재 프로세스 토큰에 SeSecurityPrivilege를 활성화합니다."""
        try:
            # 현재 프로세스의 토큰을 엽니다.
            flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(), flags)
            
            # SeSecurityPrivilege의 LUID(로컬 고유 식별자)를 찾습니다.
            id = win32security.LookupPrivilegeValue(None, win32security.SE_SECURITY_NAME)
            
            # 권한을 활성화 상태로 설정합니다.
            newPrivileges = [(id, win32security.SE_PRIVILEGE_ENABLED)]
            win32security.AdjustTokenPrivileges(htoken, 0, newPrivileges)
            self.logger.info("SeSecurityPrivilege 권한 활성화 성공")
        except Exception as e:
            self.logger.error(f"권한 활성화 실패: {e}")

    def scan(self) -> Dict[str, Any]:
        self.logger.info("Windows 보안 이벤트 로그 스캔 시작...")
        
        if win32evtlog is None:
            return {"error": "pywin32 not installed"}

        # 스캔 전 권한부터 먼저 획득합니다.
        self.enable_security_privilege()

        server = 'localhost'
        logtype = 'Security'
        suspicious_events = []
        
        try:
            hand = win32evtlog.OpenEventLog(server, logtype)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            for event in events:
                event_id = event.EventID & 0xFFFF 
                if event_id in self.config.target_event_ids:
                    suspicious_events.append({
                        "event_id": event_id,
                        "time_generated": event.TimeGenerated.Format() if event.TimeGenerated else "Unknown",
                        "source": event.SourceName,
                    })
                if len(suspicious_events) >= 10:
                    break
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            self.logger.error(f"이벤트 로그 접근 실패: {e}")
            return {"error": str(e)}
            
        return {"monitored_events_found": suspicious_events}