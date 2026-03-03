import win32api
import win32file
from typing import Dict, Any
from scanners.base import SystemScanner

class UsbScanner(SystemScanner):
    @property
    def scanner_name(self) -> str:
        return "usb_info"

    def scan(self) -> Dict[str, Any]:
        self.logger.info("🔌 USB 및 이동식 매체 연결 상태 스캔 시작...")
        usb_drives = []
        
        try:
            # 시스템의 모든 논리 드라이브 문자를 가져옵니다 (예: 'C:\\\x00D:\\\x00')
            drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
            
            for drive in drives:
                # 드라이브 타입이 '이동식 매체(REMOVABLE)'인지 확인
                if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                    try:
                        # 볼륨 이름(USB 이름) 가져오기 시도
                        volume_info = win32api.GetVolumeInformation(drive)
                        name = volume_info[0] if volume_info[0] else "Unknown USB"
                    except Exception:
                        name = "Access Denied / Unformatted"
                        
                    usb_drives.append({
                        "drive_letter": drive,
                        "volume_name": name
                    })
        except Exception as e:
            self.logger.error(f"USB 스캔 중 오류 발생: {e}")
            return {"error": str(e), "connected_usbs": [], "count": 0}
                
        return {
            "connected_usbs": usb_drives,
            "count": len(usb_drives)
        }