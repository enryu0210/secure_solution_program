# secure_solution_program — 프로젝트 개요

## 제품 정의
- **타겟**: B2B 중소기업(SME) 관리자 (보안 비전문가)
- **핵심 가치**: PC 보안 상태를 자동 수집·AI 분석하여 한국어 리포트로 제공
- **차별화 의도**: 보안 지식이 없는 관리자도 즉시 조치 가능한 가이드 제공

## 아키텍처

| 영역 | 위치 | 기술 스택 |
|---|---|---|
| **에이전트** (PC 설치형) | `src/` | Python · pywin32 · psutil · watchdog |
| **백엔드** (수집/분석 서버) | `backend/` | FastAPI · SQLite · Ollama 클라이언트 |
| **프론트엔드** (대시보드) | `frontend/index.html` | 단일 HTML (모듈화 예정) |
| **AI 분석 모델** | 로컬 Ollama | `gemma4:latest` (8B, `.env`로 변경 가능) |

## 에이전트 스캐너 (6종)
`src/scanners/` 디렉토리:
- `process.py` — 프로세스 정보/의심 프로세스
- `network.py` — 네트워크 포트/연결
- `event_log.py` — Windows 이벤트 로그
- `software.py` — 설치 소프트웨어/취약점
- `ransomware.py` — 랜섬웨어 허니팟 + 파일 변조 감시
- `usb.py` — USB 디바이스 감시

## 백엔드 주요 엔드포인트

| 메서드 | 경로 | 역할 |
|---|---|---|
| `POST` | `/api/v1/report` | 풀 스캔 리포트 수신 + AI 분석 백그라운드 트리거 |
| `POST` | `/api/v1/agent/{id}/realtime` | 3초마다 프로세스 정보 갱신 + C&C 명령 회수 |
| `POST` | `/api/v1/agent/{id}/command` | 관리자 명령 큐잉 (`kill_process`, `block_port` 등) |
| `POST` | `/api/v1/agent/{id}/reset` | 랜섬웨어 경고 해제 |
| `GET` | `/api/v1/dashboard` | 전체 에이전트 조회 |
| `GET` | `/api/v1/health` | 헬스체크 (DB + Ollama 상태 + 모델 설치 여부) |

## 운영 정보
- **GitHub**: <https://github.com/enryu0210/secure_solution_program>
- **브랜치**: 작업용 `develop`, 메인 `main`
- **포트**: 백엔드 `28080`
- **로그**: `backend/logs/server.log` (5MB×5 회전)

## 보안 정책
- 외부 LLM API 사용 금지 — 본 프로젝트는 Groq → Ollama 로컬 LLM으로 옮긴 이력이 있음 (외부 API 의존 제거 목적)
- `liteLLM` 라이브러리 사용 금지 (보안 이슈 발견)
