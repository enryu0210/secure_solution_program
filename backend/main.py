import os
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime
import uvicorn
from groq import Groq
from dotenv import load_dotenv # 추가된 부분

# ==========================================
# 1. 환경 변수 로드 및 Groq 클라이언트 초기화
# ==========================================
# 같은 폴더에 있는 .env 파일을 읽어옵니다.
load_dotenv()

# os.getenv를 통해 API 키를 안전하게 가져옵니다.
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# 키가 제대로 로드되지 않았을 때를 대비한 방어 코드
if not GROQ_API_KEY:
    raise ValueError("🚨 .env 파일에서 GROQ_API_KEY를 찾을 수 없습니다! 설정 파일을 확인해 주세요.")

client = Groq(api_key=GROQ_API_KEY)

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
    error: Optional[str] = None

class NetworkInfo(BaseModel):
    monitored_ports_active: List[Dict[str, Any]] = []
    error: Optional[str] = None

class EventLogInfo(BaseModel):
    monitored_events_found: List[Dict[str, Any]] = []
    error: Optional[str] = None

class AgentPayload(BaseModel):
    machine_id: str 
    process_info: ProcessInfo = Field(default_factory=ProcessInfo)
    network_info: NetworkInfo = Field(default_factory=NetworkInfo)
    event_log_info: EventLogInfo = Field(default_factory=EventLogInfo)

connected_agents_db = {}

def analyze_security_with_ai(machine_id: str, payload_data: dict):
    print(f"[{machine_id}] 🤖 AI 보안 분석을 시작합니다...")
    
    system_prompt = """
    당신은 B2B 중소기업을 위한 최고 수준의 사이버 보안 전문가입니다. 
    제공되는 JSON 형태의 시스템 스캔 데이터를 분석하여 다음을 수행하세요:
    1. 현재 시스템의 전반적인 보안 상태를 요약하세요.
    2. 의심스러운 프로세스, 열려있는 취약 포트, 보안 이벤트 로그 중 위험 요소가 있다면 지적하세요.
    3. 비전문가인 관리자도 이해할 수 있는 쉬운 언어로 해결책(솔루션)을 제시하세요.
    답변은 반드시 한국어로 작성하고, 마크다운 형식을 사용하여 가독성 있게 작성하세요.
    """
    
    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": str(payload_data)}
            ],
            model="llama-3.3-70b-versatile", 
            temperature=0.2,
        )
        
        ai_report = chat_completion.choices[0].message.content
        
        if machine_id in connected_agents_db:
            connected_agents_db[machine_id]["ai_analysis"] = ai_report
            print(f"[{machine_id}] ✅ AI 분석 완료 및 저장 성공!")
            
    except Exception as e:
        print(f"[{machine_id}] ❌ AI 분석 중 오류 발생: {e}")
        if machine_id in connected_agents_db:
            connected_agents_db[machine_id]["ai_analysis"] = "AI 분석을 일시적으로 사용할 수 없습니다."


@app.post("/api/v1/report")
async def receive_report(payload: AgentPayload, background_tasks: BackgroundTasks):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload_dict = payload.model_dump()
    
    connected_agents_db[payload.machine_id] = {
        "last_updated": current_time,
        "security_data": payload_dict,
        "ai_analysis": "분석 중..."
    }
    print(f"[{current_time}] 🚨 리포트 수신 완료: {payload.machine_id}")
    
    background_tasks.add_task(analyze_security_with_ai, payload.machine_id, payload_dict)
    
    return {"status": "success", "message": "데이터 수집 완료. AI가 분석을 시작합니다."}

@app.get("/api/v1/dashboard")
async def get_dashboard_data():
    return {
        "total_connected_agents": len(connected_agents_db),
        "agents": connected_agents_db
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
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)