import json
import os
from dataclasses import dataclass
from typing import List

@dataclass
class AgentConfig:
    target_ports: List[int]
    suspicious_process_names: List[str]
    target_event_ids: List[int] # 추가된 부분

def load_config(config_path: str = "../assets/config.json") -> AgentConfig:
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"설정 파일을 찾을 수 없습니다: {config_path}")
        
    with open(config_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    return AgentConfig(
        target_ports=data.get("target_ports", []),
        suspicious_process_names=data.get("suspicious_process_names", []),
        target_event_ids=data.get("target_event_ids", []) # 추가된 부분
    )