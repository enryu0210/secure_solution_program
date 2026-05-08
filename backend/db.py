"""
SQLite 기반 영속화 모듈.

기존 backend/main.py 안의 인메모리 dict(connected_agents_db)를 그대로 대체하기 위해
'드롭인 교체'를 목표로 설계했습니다. 즉, 호출부가 받던 dict 형태(키: machine_id,
값: {last_updated, security_data, ai_analysis, pending_command})를 그대로 반환합니다.

설계 메모:
- 동시 읽기 성능을 위해 WAL(Write-Ahead Logging) 모드를 사용합니다.
- 쓰기 경합은 모듈 단위 _write_lock으로 직렬화합니다.
  (FastAPI 백그라운드 태스크 + 실시간 폴링이 동시에 같은 행을 건드릴 수 있어
  단순 SELECT-then-UPDATE 패턴의 레이스를 방지하기 위함입니다.)
- security_data, pending_command 등 가변 구조 필드는 JSON 텍스트로 저장합니다.
  중소기업(SME) 규모에선 정규화 비용 대비 이득이 크지 않다고 판단했습니다.
"""
import json
import os
import sqlite3
import threading
from typing import Any, Dict, Optional, Union

# 현재 파일(backend/db.py) 기준으로 backend/agent_state.db 경로를 잡습니다.
# 서버 작업 디렉터리와 무관하게 항상 동일한 위치를 가리키도록 절대경로 사용.
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(_BASE_DIR, "agent_state.db")

# 쓰기 경합 직렬화용 모듈 락. SQLite 자체 락도 있지만,
# SELECT 후 UPDATE 패턴(예: pop_pending_command)의 원자성을 위해 추가로 둡니다.
_write_lock = threading.Lock()

# 초기화 1회 보장용
_init_lock = threading.Lock()
_initialized = False


def _connect() -> sqlite3.Connection:
    """
    각 호출마다 새 커넥션을 만들어 돌려줍니다.
    - check_same_thread=False : FastAPI 워커/백그라운드 스레드 간 공유 안전.
    - timeout=10.0 : 다른 쓰기가 진행 중일 때 잠시 대기.
    - row_factory=sqlite3.Row : 컬럼명으로 접근 가능하게 설정.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    앱 부팅 시 1회 호출. 테이블/PRAGMA를 세팅합니다.
    여러 번 호출돼도 안전합니다(idempotent).
    """
    global _initialized
    with _init_lock:
        if _initialized:
            return
        with _connect() as conn:
            # WAL: 읽기-쓰기 동시성 향상. synchronous=NORMAL: 디스크 fsync 빈도 완화(성능↑).
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS agents (
                    machine_id      TEXT PRIMARY KEY,
                    last_updated    TEXT NOT NULL,
                    security_data   TEXT NOT NULL,   -- JSON 직렬화
                    ai_analysis     TEXT,
                    pending_command TEXT             -- JSON 직렬화, NULL 가능
                );
                """
            )
            conn.commit()
        _initialized = True


def _row_to_agent(row: sqlite3.Row) -> Dict[str, Any]:
    """DB 행을 기존 dict 포맷과 동일한 구조의 파이썬 dict로 변환합니다."""
    pending_raw = row["pending_command"]
    return {
        "last_updated": row["last_updated"],
        "security_data": json.loads(row["security_data"]),
        "ai_analysis": row["ai_analysis"],
        "pending_command": json.loads(pending_raw) if pending_raw else None,
    }


# ---------------------------------------------------------------------------
# 조회 계열
# ---------------------------------------------------------------------------
def get_agent(machine_id: str) -> Optional[Dict[str, Any]]:
    """단일 에이전트 조회. 없으면 None."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM agents WHERE machine_id = ?",
            (machine_id,),
        ).fetchone()
    return _row_to_agent(row) if row else None


def get_all_agents() -> Dict[str, Dict[str, Any]]:
    """대시보드용 전체 조회. {machine_id: agent_dict} 형식."""
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM agents").fetchall()
    return {row["machine_id"]: _row_to_agent(row) for row in rows}


def agent_exists(machine_id: str) -> bool:
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM agents WHERE machine_id = ?",
            (machine_id,),
        ).fetchone()
    return row is not None


def total_agents() -> int:
    with _connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS c FROM agents").fetchone()
    return int(row["c"]) if row else 0


# ---------------------------------------------------------------------------
# 갱신 계열
# ---------------------------------------------------------------------------
def upsert_agent_full(
    machine_id: str,
    last_updated: str,
    security_data: Dict[str, Any],
    ai_analysis: str,
    pending_command: Optional[Union[str, Dict[str, Any]]] = None,
) -> None:
    """
    풀 리포트(60초 주기) 수신 시 호출되는 통합 upsert.
    pending_command는 호출 직전 pop된 후이므로 보통 None을 넘깁니다.
    """
    payload = (
        machine_id,
        last_updated,
        json.dumps(security_data, ensure_ascii=False),
        ai_analysis,
        json.dumps(pending_command, ensure_ascii=False) if pending_command is not None else None,
    )
    with _write_lock, _connect() as conn:
        conn.execute(
            """
            INSERT INTO agents (machine_id, last_updated, security_data, ai_analysis, pending_command)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(machine_id) DO UPDATE SET
                last_updated    = excluded.last_updated,
                security_data   = excluded.security_data,
                ai_analysis     = excluded.ai_analysis,
                pending_command = excluded.pending_command
            """,
            payload,
        )
        conn.commit()


def update_ai_analysis(machine_id: str, ai_analysis: str) -> bool:
    """AI 분석 결과만 갱신. 행이 없으면 False."""
    with _write_lock, _connect() as conn:
        cur = conn.execute(
            "UPDATE agents SET ai_analysis = ? WHERE machine_id = ?",
            (ai_analysis, machine_id),
        )
        conn.commit()
    return cur.rowcount > 0


def update_process_info(machine_id: str, process_info: Dict[str, Any]) -> bool:
    """
    실시간 엔드포인트(3초 주기)에서 process_info만 부분 업데이트.
    - JSON 컬럼 통째로 다시 쓰지만, _write_lock으로 직렬화되어 안전합니다.
    - 행이 없으면 False (실시간 엔드포인트는 풀 리포트 이전에 호출되지 않는다고 가정).
    """
    with _write_lock, _connect() as conn:
        row = conn.execute(
            "SELECT security_data FROM agents WHERE machine_id = ?",
            (machine_id,),
        ).fetchone()
        if not row:
            return False
        sec = json.loads(row["security_data"])
        sec["process_info"] = process_info
        conn.execute(
            "UPDATE agents SET security_data = ? WHERE machine_id = ?",
            (json.dumps(sec, ensure_ascii=False), machine_id),
        )
        conn.commit()
    return True


def reset_ransomware_state(machine_id: str) -> bool:
    """
    랜섬웨어 경고 즉시 해제.
    - 서버 측 표시 데이터를 즉시 Safe로 초기화하고
    - 에이전트에게 보낼 'reset_ransomware' 명령을 큐잉하며
    - AI 분석을 다시 돌리도록 '분석 중...' 상태로 되돌립니다.
    행이 없으면 False.
    """
    with _write_lock, _connect() as conn:
        row = conn.execute(
            "SELECT security_data FROM agents WHERE machine_id = ?",
            (machine_id,),
        ).fetchone()
        if not row:
            return False
        sec = json.loads(row["security_data"])
        ransom = sec.get("ransomware_info") or {}
        ransom["status"] = "Safe"
        ransom["tampered_files"] = []
        ransom["suspended_processes"] = []
        sec["ransomware_info"] = ransom

        conn.execute(
            """
            UPDATE agents
            SET security_data   = ?,
                ai_analysis     = '분석 중...',
                pending_command = ?
            WHERE machine_id = ?
            """,
            (
                json.dumps(sec, ensure_ascii=False),
                json.dumps("reset_ransomware"),  # 단순 문자열 명령 (에이전트 측 분기 그대로)
                machine_id,
            ),
        )
        conn.commit()
    return True


def set_pending_command(
    machine_id: str,
    command: Union[str, Dict[str, Any]],
) -> bool:
    """
    C&C 명령 큐잉. 기존 pending이 있으면 덮어씁니다(원본 동작 유지).
    행이 없으면 False.
    """
    with _write_lock, _connect() as conn:
        cur = conn.execute(
            "UPDATE agents SET pending_command = ? WHERE machine_id = ?",
            (json.dumps(command, ensure_ascii=False), machine_id),
        )
        conn.commit()
    return cur.rowcount > 0


def pop_pending_command(machine_id: str) -> Optional[Union[str, Dict[str, Any]]]:
    """
    대기 중인 명령을 회수하면서 동시에 NULL로 비웁니다(원자적).
    명령이 없거나 행 자체가 없으면 None.
    """
    with _write_lock, _connect() as conn:
        row = conn.execute(
            "SELECT pending_command FROM agents WHERE machine_id = ?",
            (machine_id,),
        ).fetchone()
        if not row or not row["pending_command"]:
            return None
        cmd_raw = row["pending_command"]
        conn.execute(
            "UPDATE agents SET pending_command = NULL WHERE machine_id = ?",
            (machine_id,),
        )
        conn.commit()
    return json.loads(cmd_raw)
