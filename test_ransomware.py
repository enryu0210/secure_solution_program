import os
import time

print("😈 가짜 랜섬웨어 스크립트 실행됨!")
print("1초 뒤 미끼 파일을 수정(암호화 흉내)합니다...")
time.sleep(1)

# 에이전트가 감시 중인 허니팟 경로
honeypot_dir = os.path.join(os.environ.get('PUBLIC', 'C:\\Users\\Public'), "Documents", "SystemBackup_DoNotModify")
target_file = os.path.join(honeypot_dir, "financial_records_2026.xlsx")

try:
    if os.path.exists(target_file):
        # 파일 내용을 수정해서 감시 로그를 트리거함 (핸들 열어두기)
        f = open(target_file, "a", encoding="utf-8")
        f.write("\n[Fake Ransomware] This file has been encrypted!")
        f.flush() # 물리적 디스크에 바로 쓰기
        
        print("✅ 가짜 암호화 성공! 에이전트가 나를 멈출 것입니다.")
        
        # 파일 핸들을 열어둔 채로 대기해야 에이전트가 내가 범인인 걸 찾아(psutil)냅니다!
        count = 1
        while True:
            print(f"내가 살아있나? 생존 시간: {count}초")
            time.sleep(1)
            count += 1
    else:
        print("❌ 미끼 파일이 아직 생성되지 않았습니다. 에이전트(src/main.py)를 먼저 실행해 주세요.")
except Exception as e:
    print(f"오류 발생: {e}")
