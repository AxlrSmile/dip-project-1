"""
T1087: Account Discovery (Обнаружение учетных записей)
Тактика: Discovery (TA0007)
"""

import subprocess
import platform
from core.base_technique import BaseTechnique
from core.models import TechniqueMeta, Tactic, Severity, AttackStatus


class T1087AccountDiscovery(BaseTechnique):
    def get_meta(self) -> TechniqueMeta:
        return TechniqueMeta(
            technique_id="T1087",
            name="Account Discovery (Обнаружение локальных пользователей)",
            tactic=Tactic.DISCOVERY,
            description="Злоумышленники собирают списки локальных и доменных пользователей для подготовки атак подбора паролей и горизонтального перемещения.",
            severity=Severity.LOW,
            mitre_url="https://attack.mitre.org/techniques/T1087/",
            mitre_detection_tips="События аудита создания процессов для net user, net localgroup, Get-LocalUser.",
            remediation="Включение детального аудита процессов (Process Creation 4688) и ограничение прав выполнения утилит администрирования."
        )

    def run_simulation(self) -> tuple[AttackStatus, str, str, str]:
        cmd = "net user" if platform.system() == "Windows" else "cat /etc/passwd"
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
