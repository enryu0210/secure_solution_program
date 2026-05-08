# secure_solution_program — 프로젝트 가이드

자세한 아키텍처/엔드포인트는 `docs/PROJECT_OVERVIEW.md`, 작업 우선순위는 `docs/ROADMAP.md` 참고.

## 환경/포트
- 백엔드: `http://localhost:28080` (FastAPI, `backend/main.py`)
- Ollama: `http://localhost:11434`, 기본 모델 `gemma4:latest` (`.env`로 변경)
- DB: `backend/agent_state.db` (SQLite, gitignore됨)
- 로그: `backend/logs/server.log` (5MB×5 회전, gitignore됨)

## 자주 쓰는 명령
- 헬스체크: `curl http://localhost:28080/api/v1/health`
- Ollama 모델 목록: `curl http://localhost:11434/api/tags`
- 백엔드 실행: `python backend/main.py`
- 문법 검증: `python -m py_compile backend/main.py backend/db.py backend/logger.py`

## Windows 환경 quirks
- PowerShell/cmd 콘솔(cp949)은 한글·이모지 `print()` 출력 시 깨짐 → 결과를 파일에 저장한 뒤 `Read`로 확인할 것.
- 경로에 한글이 포함되므로 항상 절대경로 + 따옴표 사용. `git -C "<path>"` 형태 권장.

## LLM 호출 규칙 (Ollama/Gemma)
- payload는 `json.dumps(data, ensure_ascii=False, indent=2)`로 직렬화. `str(dict)` 금지 (Python repr이 되어 모델이 JSON으로 응답함).
- user 메시지에 데이터만 넣지 말 것. "이 데이터를 ~형식으로 분석하라"는 명시적 작업 지시를 함께 포함.
- 시스템 프롬프트는 모듈 상수 + `textwrap.dedent("""\...""").strip()` 패턴 사용.
- 응답 양식 강제는 `[절대 규칙]` 섹션에 "JSON·영어·코드블록 금지, 되묻지 말 것" 명시.

## 코드 스타일
- `print` 금지. `from logger import logger` 후 `logger.info/error("...", arg, exc_info=True)` 사용.
- 새 파이썬 파일은 백엔드의 경우 `backend/`, 에이전트는 `src/scanners/` 컨벤션 따를 것.
