"""
Модели данных для платформы эмуляции атак MITRE ATT&CK (BAS)
Разработано для дипломного проекта по специальности "Информационная безопасность"
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class Tactic(str, Enum):
    INITIAL_ACCESS = "Initial Access (Первоначальный доступ)"
    EXECUTION = "Execution (Выполнение)"
    PERSISTENCE = "Persistence (Закрепление в системе)"
    PRIVILEGE_ESCALATION = "Privilege Escalation (Повышение привилегий)"
    DEFENSE_EVASION = "Defense Evasion (Обход защиты)"
    CREDENTIAL_ACCESS = "Credential Access (Получение учетных данных)"
    DISCOVERY = "Discovery (Исследование системы)"
    LATERAL_MOVEMENT = "Lateral Movement (Горизонтальное перемещение)"
    COLLECTION = "Collection (Сбор данных)"
    EXFILTRATION = "Exfiltration (Эксфильтрация / Кража данных)"
    IMPACT = "Impact (Воздействие)"


class AttackStatus(str, Enum):
    PENDING = "PENDING"          # Ожидает запуска
    RUNNING = "RUNNING"          # Выполняется
    VULNERABLE = "VULNERABLE"    # Атака успешно завершилась (СЗИ НЕ заблокировали)
    PROTECTED = "PROTECTED"      # Атака заблокирована или зафиксирована СЗИ
    ERROR = "ERROR"              # Ошибка при выполнении сценария


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TechniqueMeta(BaseModel):
    technique_id: str = Field(..., description="ID техники по MITRE ATT&CK, например T1082")
    name: str = Field(..., description="Название техники")
    tactic: Tactic = Field(..., description="Тактика MITRE ATT&CK")
    description: str = Field(..., description="Описание эмулируемой угрозы")
    severity: Severity = Field(default=Severity.MEDIUM)
    mitre_url: str = Field(..., description="Ссылка на официальную базу MITRE ATT&CK")
    mitre_detection_tips: str = Field(default="", description="Рекомендации MITRE по обнаружению")
    remediation: str = Field(default="", description="Меры нейтрализации (рекомендации ФСТЭК/CIS)")


class ExecutionResult(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    status: AttackStatus
    executed_at: str = Field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    execution_time_ms: float = 0.0
    command_executed: str = ""
    stdout: str = ""
    stderr: str = ""
    cleanup_success: bool = True
    cleanup_log: str = ""
    detection_verified: bool = False
    telemetry_source: str = ""
    remediation_advice: str = ""


class RunSummary(BaseModel):
    run_id: str
    timestamp: str
    target_host: str
    os_info: str
    total_executed: int
    vulnerable_count: int     # Уязвимо (атака прошла успешно без сопротивления)
    protected_count: int      # Защищено (СЗИ перехватили / предотвратили)
    error_count: int
    security_score: float     # Рейтинг защищенности (0.0% - 100.0%)
    results: List[ExecutionResult]
