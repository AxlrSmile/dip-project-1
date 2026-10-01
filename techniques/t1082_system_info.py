"""
T1082: System Information Discovery (Сбор информации о системе)
Тактика: Discovery (TA0007)
"""

import subprocess
import platform
from core.base_technique import BaseTechnique
from core.models import TechniqueMeta, Tactic, Severity, AttackStatus


class T1082SystemInfo(BaseTechnique):
    def get_meta(self) -> TechniqueMeta:
        return TechniqueMeta(
            technique_id="T1082",
            name="System Information Discovery (Сбор сведений о системе)",
            tactic=Tactic.DISCOVERY,
            description="Злоумышленники используют легитимные системные утилиты для получения детальных сведений об ОС, версии ядра, патчах и оборудовании.",
            severity=Severity.LOW,
            mitre_url="https://attack.mitre.org/techniques/T1082/",
            mitre_detection_tips="Мониторинг запуска команд systeminfo, hostname, uname, вызовов WMI Win32_OperatingSystem.",
            remediation="Ограничение использования средств инвентаризации непривилегированными пользователями (AppLocker, SRP, политики ФСТЭК)."
        )

    def run_simulation(self) -> tuple[AttackStatus, str, str, str]:
        cmd = "systeminfo" if platform.system() == "Windows" else "uname -a"
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                # Если команда выполнилась беспрепятственно и вернула данные
                return AttackStatus.VULNERABLE, cmd, res.stdout, res.stderr
            else:
                return AttackStatus.PROTECTED, cmd, res.stdout, res.stderr
        except Exception as e:
            return AttackStatus.ERROR, cmd, "", str(e)

    def cleanup(self) -> tuple[bool, str]:
        return True, "Команда только для чтения, артефакты отсутствуют"
