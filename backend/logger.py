"""
백엔드 전역 로거 설정.

[설계 의도]
- 운영 환경에서 print() 만으로는 로그 레벨/타임스탬프/파일 보존이 안 되어
  장애 추적이 어렵기 때문에 표준 logging 모듈로 일원화.
- 콘솔(stdout) + 파일(rotating) 동시 출력.
  · 콘솔: 개발 중 실시간 확인용
  · 파일: 운영 시 사후 분석용 (자동 회전으로 디스크 폭주 방지)
- 어디서든 `from logger import logger` 한 줄로 동일한 로거 사용.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

# 로그 파일 위치: backend/logs/server.log
# - logs 폴더는 처음 호출 시 자동 생성
# - 파일 한 개당 최대 5MB, 최근 5개까지 보관 (총 약 25MB)
_LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
_LOG_FILE = os.path.join(_LOG_DIR, "server.log")
_MAX_BYTES = 5 * 1024 * 1024  # 5MB
_BACKUP_COUNT = 5

# 환경변수 LOG_LEVEL로 외부 제어 가능 (기본 INFO).
# 디버깅 시: LOG_LEVEL=DEBUG 로 실행
_LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()


def _build_logger() -> logging.Logger:
    """애플리케이션 전용 로거를 1회만 구성하고 반환합니다."""
    logger = logging.getLogger("secure_solution")
    logger.setLevel(_LOG_LEVEL)

    # 중복 핸들러 등록 방지 (uvicorn --reload 시 모듈이 재로드될 수 있음)
    if logger.handlers:
        return logger

    # 로그 폴더가 없으면 생성 (운영 시 첫 부팅에서도 안전하도록)
    os.makedirs(_LOG_DIR, exist_ok=True)

    # 공통 포맷: 시간 / 레벨 / 로거명 / 메시지
    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # 콘솔 출력 (개발 중 즉시 확인)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)
    logger.addHandler(console_handler)

    # 파일 출력 (운영 시 사후 분석)
    # - encoding=utf-8: 한글 깨짐 방지 (Windows 환경 필수)
    file_handler = RotatingFileHandler(
        _LOG_FILE,
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    # 루트 로거로 전파 방지 (uvicorn 기본 로거와 중복 출력 방지)
    logger.propagate = False

    return logger


# 모듈 임포트 시점에 1회만 구성. 다른 파일은 이 변수를 import 해서 사용.
logger = _build_logger()
