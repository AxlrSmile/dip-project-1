"""
T1027: Obfuscated Files or Information
Тактика: Defense Evasion (TA0005)
"""

import base64
import subprocess
import platform
from core.base_technique import BaseTechnique
from core.models import TechniqueMeta, Tactic, Severity, AttackStatus


class T1027Obfuscation(BaseTechnique):
    def get_meta(self) -> TechniqueMeta:
        return TechniqueMeta(
            technique_id="T1027",
            name="Obfuscated Files or Information (Обфускация команд и пейлоадов)",
            tactic=Tactic.DEFENSE_EVASION,
            description="Злоумышленники кодируют и обфусцируют исполняемый код (Base64, xor, переменные окружения), чтобы обойти сигнатурный анализ антивирусов и IDS.",
            severity=Severity.HIGH,
            mitre_url="https://attack.mitre.org/techniques/T1027/",
            mitre_detection_tips="Включение PowerShell Script Block Logging (Event ID 4104), интеграция AMSI, детект длинных аргументов -EncodedCommand.",
            remediation="Включение блокировки неинтерактивного PowerShell в AppLocker, активация Constrained Language Mode, аудит декодирования AMSI."
        )

    def run_simulation(self) -> tuple[AttackStatus, str, str, str]:
        # Безопасная тестовая строка: Write-Output 'Canary_Obfuscation_Test_OK'
        raw_cmd = "Write-Output 'Canary_Obfuscation_Test_OK'"
        
        if platform.system() == "Windows":
            # PowerShell ожидает UTF-16LE для Base64
            encoded = base64.b64encode(raw_cmd.encode("utf-16le")).decode("utf-8")
            full_cmd = f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded}"
        else:
            encoded = base64.b64encode(f"echo '{raw_cmd}'".encode()).decode("utf-8")
            full_cmd = f"echo {encoded} | base64 -d | sh"

        try:
            res = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, timeout=10)
            if res.returncode == 0 and "Canary_Obfuscation_Test_OK" in res.stdout:
                return (
                    AttackStatus.VULNERABLE,
                    full_cmd,
                    "Обфусцированная Base64-команда успешно выполнена без блокировки со стороны AMSI/СЗИ.",
                    res.stderr
                )
            else:
                return AttackStatus.PROTECTED, full_cmd, res.stdout, res.stderr
        except Exception as e:
            return AttackStatus.ERROR, full_cmd, "", str(e)

    def cleanup(self) -> tuple[bool, str]:
        return True, "Команда выполнялась только в памяти процесса, артефакты отсутствуют"
