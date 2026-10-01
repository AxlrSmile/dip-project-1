"""
T1057: Process Discovery (Исследование запущенных процессов и СЗИ)
Тактика: Discovery (TA0007)
"""

import subprocess
import platform
from core.base_technique import BaseTechnique
from core.models import TechniqueMeta, Tactic, Severity, AttackStatus


class T1057ProcessDiscovery(BaseTechnique):
    def get_meta(self) -> TechniqueMeta:
        return TechniqueMeta(
            technique_id="T1057",
            name="Process Discovery (Инвентаризация процессов и проверка наличия СЗИ)",
            tactic=Tactic.DISCOVERY,
            description="Злоумышленники получают список активных процессов для поиска средств защиты (антивирусов, EDR, SIEM-агентов) с целью их дальнейшего обхода.",
            severity=Severity.LOW,
            mitre_url="https://attack.mitre.org/techniques/T1057/",
            mitre_detection_tips="Отслеживание массовых запросов к списку процессов (tasklist.exe, ps, Get-Process).",
            remediation="Использование средств Endpoint Detection and Response (EDR) для выявления разведывательной активности."
        )

    def run_simulation(self) -> tuple[AttackStatus, str, str, str]:
        cmd = "tasklist" if platform.system() == "Windows" else "ps aux"
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                return AttackStatus.VULNERABLE, cmd, res.stdout, res.stderr
            else:
                return AttackStatus.PROTECTED, cmd, res.stdout, res.stderr
        except Exception as e:
            return AttackStatus.ERROR, cmd, "", str(e)

    def cleanup(self) -> tuple[bool, str]:
        return True, "Команда разведки, артефакты отсутствуют"
