import os
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime
import uvicorn
import ollama
from dotenv import load_dotenv

# SQLite 영속화 모듈 (기존 인메모리 dict를 대체).
# - 같은 폴더(backend/)에 있는 db.py를 직접 임포트.
# - 서버 재시작 시에도 에이전트 상태/대기 명령이 유지되도록 합니다.
import db

# ==========================================
# 1. 환경 변수 로드 및 Ollama 클라이언트 초기화
# ==========================================
# 같은 폴더에 있는 .env 파일을 읽어옵니다.
load_dotenv()

# Ollama 로컬 데몬 주소와 사용 모델은 .env로 외부화합니다.
# - 기본 호스트: http://localhost:11434 (Ollama 표준 포트)
# - 기본 모델 : gemma4 (Google Gemma 라인 최신 버전)
#   ※ 사이즈 선택 가이드:
#     · 가벼운 환경(노트북, GPU 없음)        → OLLAMA_MODEL=gemma4:e2b
#     · 일반 데스크톱(VRAM ~12GB)            → OLLAMA_MODEL=gemma4:e4b
#     · 워크스테이션(VRAM 20GB+)             → OLLAMA_MODEL=gemma4:26b 또는 :31b
#     · 자원 0(클라우드 위임)                → OLLAMA_MODEL=gemma4:31b-cloud
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma4")

# Ollama 클라이언트는 내부적으로 httpx를 쓰므로, 호스트만 지정하면 끝입니다.
ollama_client = ollama.Client(host=OLLAMA_HOST)

app = FastAPI(title="보안 에이전트 수집 및 AI 분석 서버")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # 실제 운영 환경에서는 허용할 도메인만 명시해야 함
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- (이하 Pydantic 모델 및 라우터 코드는 기존과 완벽히 동일합니다) ---
class ProcessInfo(BaseModel):
    total_processes: int = 0
    suspicious_processes: List[Dict[str, Any]] = []
    running_processes: List[Dict[str, Any]] = []
    error: Optional[str] = None

class NetworkInfo(BaseModel):
    monitored_ports_active: List[Dict[str, Any]] = []
    error: Optional[str] = None

class EventLogInfo(BaseModel):
    monitored_events_found: List[Dict[str, Any]] = []
    error: Optional[str] = None

class SoftwareInfo(BaseModel):
    total_installed: int = 0
    software_list: List[Dict[str, Any]] = []
    error: Optional[str] = None
    
class RansomwareInfo(BaseModel):
    status: str = "Safe"
    tampered_files: List[str] = []
    suspended_processes: List[Dict[str, Any]] = []
    error: Optional[str] = None

class UsbInfo(BaseModel):
    connected_usbs: List[Dict[str, Any]] = []
    count: int = 0
    error: Optional[str] = None

class AgentPayload(BaseModel):
    machine_id: str 
    process_info: ProcessInfo = Field(default_factory=ProcessInfo)
    network_info: NetworkInfo = Field(default_factory=NetworkInfo)
    event_log_info: EventLogInfo = Field(default_factory=EventLogInfo)
    software_info: SoftwareInfo = Field(default_factory=SoftwareInfo)
    ransomware_info: RansomwareInfo = Field(default_factory=RansomwareInfo)
    usb_info: UsbInfo = Field(default_factory=UsbInfo)

# 앱 부팅 시 SQLite 스키마/PRAGMA 1회 초기화.
# (모듈 로드 타이밍에 호출되므로, --reload 시에도 매번 idempotent하게 동작합니다.)
db.init_db()


def analyze_security_with_ai(machine_id: str, payload_data: dict):
    print(f"[{machine_id}] 🤖 AI 보안 분석을 시작합니다...")
    
    system_prompt = """
    당신은 B2B 중소기업(SME)을 위한 최고 수준의 사이버 보안 전문가입니다.
    제공되는 JSON 형태의 시스템 스캔 데이터(프로세스, 네트워크, 이벤트 로그, 설치된 소프트웨어, 랜섬웨어 허니팟 상태)를 꼼꼼히 분석하여, 보안 지식이 전혀 없는 비전문가 관리자도 즉시 이해하고 조치할 수 있는 보고서를 작성하세요.

    반드시 아래의 마크다운 템플릿 양식을 엄격하게 지켜서 한국어로 작성하세요 (한국어 이외의 언어는 사용하지 마세요):

    ### 📊 전반적인 보안 상태 요약
    * **상태 평가:** (데이터를 바탕으로 '안전', '주의', '심각' 중 하나로 평가)
    * **종합 요약:** (현재 시스템의 핵심 보안 이슈를 1~2줄로 요약)
    * **비즈니스 리스크:** (이 상태를 방치할 경우 기업 데이터나 업무에 미칠 수 있는 구체적인 피해 예상)

    ### 🚨 핵심 보안 위협 분석
    * **1. 랜섬웨어 및 파일 훼손 감시:** (ransomware_info를 분석. status가 CRITICAL일 경우 강력하게 경고. suspended_processes 항목이 있다면 해당 프로세스가 오탐인지 확인하도록 안내하고, 윈도우 작업 관리자에서 수동 종료 혹은 일시 중지 해제(재개)하는 가이드 포함)
    * **2. 소프트웨어 취약점 (CVE):** (software_info 분석. 해킹 타겟이 되기 쉬운 구버전 프로그램 지적)
    * **3. 프로세스 및 네트워크:** (의심스러운 프로세스나 외부로 열려있는 위험 포트 분석)
    * **4. 시스템 이벤트 로그:** (비정상적인 로그인 실패나 권한 변경 징후 분석)

    ### 🛡️ 상세 조치 가이드 (Action Items)
    탐지된 위협에 대해 즉시 실행 가능한 구체적인 가이드를 제공하세요. 두루뭉술한 조언(예: "보안을 강화하세요")은 절대 금지합니다.

    * **[발견된 위협 이름 (예: 의심스러운 3389 포트 개방)]**
      * **긴급 조치 (1시간 내):** (무엇을 당장 차단하거나 종료해야 하는지 설명)
      * **실행 방법 (상세):** (Windows 방화벽 UI 클릭 순서, 작업 관리자 조치 방법, 또는 관리자 권한 PowerShell/CMD 명령어 등 복사해서 붙여넣을 수 있는 수준으로 제공)
      * **예방책:** (재발 방지를 위한 장기적인 설정)

    * 주의사항: 발견된 특정 위협이 없다면 해당 항목은 "현재 탐지된 특이사항 없이 안전합니다. 정기적인 OS 업데이트를 유지해 주세요."라고 기재하세요.
    """
    
    try:
        # Ollama chat API 호출. options에 샘플링 파라미터를 넣는 방식.
        # temperature=0.2는 일관성 있는 보안 분석을 위해 낮게 유지.
        response = ollama_client.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": str(payload_data)},
            ],
            options={"temperature": 0.2},
        )

        # Ollama 응답 포맷: {"message": {"role": "assistant", "content": "..."}, ...}
        ai_report = response["message"]["content"]

        # SQLite에 분석 결과만 부분 갱신. 이미 행이 사라졌으면 update_ai_analysis가 False를 반환.
        if db.update_ai_analysis(machine_id, ai_report):
            print(f"[{machine_id}] ✅ AI 분석 완료 및 저장 성공!")

    except Exception as e:
        # Ollama 미기동 / 모델 미설치 같은 흔한 실수에 즉시 단서를 제공.
        # (운영자가 콘솔만 보고도 다음 액션을 알 수 있도록 한국어 힌트를 덧붙임)
        err_text = str(e).lower()
        if "model" in err_text and ("not found" in err_text or "404" in err_text):
            hint = f" (해결: 백엔드 머신에서 `ollama pull {OLLAMA_MODEL}` 실행)"
        elif "connect" in err_text or "refused" in err_text or "timeout" in err_text:
            hint = f" (해결: `ollama serve`가 실행 중인지, OLLAMA_HOST={OLLAMA_HOST} 가 맞는지 확인)"
        else:
            hint = ""

        print(f"[{machine_id}] ❌ AI 분석 중 오류 발생: {e}{hint}")
        db.update_ai_analysis(
            machine_id,
            f"AI 분석을 일시적으로 사용할 수 없습니다.{hint}",
        )


@app.post("/api/v1/report")
async def receive_report(payload: AgentPayload, background_tasks: BackgroundTasks):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload_dict = payload.model_dump()

    # 1) 대기 명령이 있으면 원자적으로 회수(=POP). 없으면 None.
    pending = db.pop_pending_command(payload.machine_id)
    command_to_send = []
    if pending:
        command_to_send.append(pending)
        # reset_ransomware 명령이라면 서버 측 표시 데이터도 즉시 Safe로 정리해줍니다.
        # (에이전트가 다음 스캔 결과를 올리기 전까지 대시보드가 잠깐 빨갛게 남는 걸 방지)
        if pending == "reset_ransomware":
            payload_dict["ransomware_info"]["status"] = "Safe"
            payload_dict["ransomware_info"]["tampered_files"] = []
            payload_dict["ransomware_info"]["suspended_processes"] = []

    # 2) 풀 리포트로 행을 통째 upsert. AI 분석은 백그라운드 태스크에서 별도로 채웁니다.
    db.upsert_agent_full(
        machine_id=payload.machine_id,
        last_updated=current_time,
        security_data=payload_dict,
        ai_analysis="분석 중...",
        pending_command=None,  # 방금 회수했으므로 비어 있는 상태로 시작
    )

    background_tasks.add_task(analyze_security_with_ai, payload.machine_id, payload_dict)

    # 에이전트에게 보내는 응답(JSON)에 'commands' 리스트를 추가해서 보냅니다.
    return {"status": "success", "commands": command_to_send}

@app.post("/api/v1/agent/{machine_id}/reset")
async def reset_agent_status(machine_id: str):
    # SQLite 트랜잭션 1회로 [표시 데이터 초기화 + 명령 큐잉 + AI 상태 리셋]을 한 번에 처리.
    if db.reset_ransomware_state(machine_id):
        return {"status": "success", "message": "경고가 해제되었습니다. 에이전트를 초기화합니다."}
    return {"status": "error", "message": "해당 에이전트를 찾을 수 없습니다."}

class CommandPayload(BaseModel):
    action: str  # 예: "kill_process", "block_port"
    target: str  # 예: "1234" (PID) 또는 "3389" (포트번호)

@app.post("/api/v1/agent/{machine_id}/command")
async def send_command_to_agent(machine_id: str, payload: CommandPayload):
    # 가장 최근 명령 1개를 덮어씌우는 기존 동작은 db.set_pending_command가 그대로 유지합니다.
    # (큐 형태 다중 명령은 별도 후속 작업으로 보류)
    command_dict = {"action": payload.action, "target": payload.target}

    if db.set_pending_command(machine_id, command_dict):
        return {"status": "success", "message": f"[{payload.action}] 명령이 {machine_id} 대기열에 추가되었습니다."}

    return {"status": "error", "message": "해당 에이전트를 찾을 수 없습니다."}

# 기존 모델들 아래에 실시간 전용 Pydantic 모델 추가
class RealtimePayload(BaseModel):
    process_info: ProcessInfo

@app.post("/api/v1/agent/{machine_id}/realtime")
async def handle_realtime_update(machine_id: str, payload: RealtimePayload):
    """3초마다 에이전트로부터 실시간 프로세스 정보를 받고, 대기 중인 C&C 명령을 반환합니다."""
    # 1. process_info만 부분 갱신. 풀 리포트 이전이면 행이 없어 False가 반환됨.
    if not db.update_process_info(machine_id, payload.process_info.model_dump()):
        return {"status": "error", "message": "에이전트 미등록"}

    # 2. 대기 명령은 원자적으로 회수.
    cmd = db.pop_pending_command(machine_id)
    commands = [cmd] if cmd else []

    return {"status": "success", "commands": commands}

@app.get("/api/v1/dashboard")
async def get_dashboard_data():
    # SQLite에서 전체 에이전트를 조회. 응답 스키마는 기존 프론트엔드가 기대하는 형태와 동일.
    agents = db.get_all_agents()
    return {
        "total_connected_agents": len(agents),
        "agents": agents,
    }

@app.get("/")
async def serve_frontend():
    # 현재 파일(backend/main.py)을 기준으로 ../frontend/index.html 경로 추적
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    html_path = os.path.join(base_dir, "frontend", "index.html")
    
    if not os.path.exists(html_path):
        return {"error": "index.html 파일을 찾을 수 없습니다. 경로를 확인하세요."}
        
    return FileResponse(html_path)

if __name__ == "__main__":
    print("🚀 보안 SaaS 수집 서버를 시작합니다...")
    uvicorn.run("main:app", host="0.0.0.0", port=28080, reload=True)