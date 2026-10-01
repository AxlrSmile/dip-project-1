"""
T1053.005: Scheduled Task/Job: Scheduled Task
Тактика: Persistence (TA0003), Execution (TA0002)
"""

import subprocess
import platform
from core.base_technique import BaseTechnique
from core.models import TechniqueMeta, Tactic, Severity, AttackStatus


class T1053ScheduledTask(BaseTechnique):
    TASK_NAME = "MitreBasCanary_Task"

    def get_meta(self) -> TechniqueMeta:
        return TechniqueMeta(
            technique_id="T1053.005",
            name="Scheduled Task (Закрепление через планировщик задач)",
            tactic=Tactic.PERSISTENCE,
            description="Злоумышленники используют планировщик задач (Task Scheduler / schtasks / cron) для закрепления в системе и отложенного запуска вредоносного кода.",
            severity=Severity.HIGH,
            mitre_url="https://attack.mitre.org/techniques/T1053/005/",
            mitre_detection_tips="События журнала Microsoft-Windows-TaskScheduler Event ID 106 (Задача зарегистрирована), Sysmon Event ID 1.",
            remediation="Ограничение прав на вызов schtasks.exe, аудит создания новых запланированных заданий, применение AppLocker."
        )

    def run_simulation(self) -> tuple[AttackStatus, str, str, str]:
        if platform.system() != "Windows":
            return AttackStatus.ERROR, "N/A", "", "Техника поддерживается только для ОС Windows"

        cmd = f'schtasks /create /tn "{self.TASK_NAME}" /tr "cmd.exe /c echo canary" /sc once /st 23:59 /f'
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                return (
                    AttackStatus.VULNERABLE,
                    cmd,
                    f"Планировщик успешно зарегистрировал тестовую задачу '{self.TASK_NAME}'",
                    res.stderr
                )
            else:
                return AttackStatus.PROTECTED, cmd, res.stdout, res.stderr
        except Exception as e:
            return AttackStatus.ERROR, cmd, "", str(e)

    def cleanup(self) -> tuple[bool, str]:
        if platform.system() != "Windows":
            return True, "Пропуск зачистки"

        cmd = f'schtasks /delete /tn "{self.TASK_NAME}" /f'
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if res.returncode == 0 or "не удается найти" in res.stderr.lower():
                return True, f"Тестовая задача '{self.TASK_NAME}' успешно удалена"
            return False, f"Ошибка удаления задачи: {res.stderr}"
        except Exception as e:
            return False, f"Исключение при зачистке: {e}"
