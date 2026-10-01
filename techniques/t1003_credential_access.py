"""
T1003: OS Credential Dumping (Эмуляция доступа к хранилищам учетных данных)
Тактика: Credential Access (TA0006)
"""

import subprocess
import platform
from core.base_technique import BaseTechnique
from core.models import TechniqueMeta, Tactic, Severity, AttackStatus

if platform.system() == "Windows":
    import winreg
else:
    winreg = None


class T1003CredentialAccessSim(BaseTechnique):
    def get_meta(self) -> TechniqueMeta:
        return TechniqueMeta(
            technique_id="T1003",
            name="OS Credential Dumping (Анализ защищенности хранилищ паролей и SAM)",
            tactic=Tactic.CREDENTIAL_ACCESS,
            description="Злоумышленники пытаются извлечь учетные данные, хэши NTLM и тикеты Kerberos из памяти процесса LSASS или веток реестра SAM/SYSTEM.",
            severity=Severity.CRITICAL,
            mitre_url="https://attack.mitre.org/techniques/T1003/",
            mitre_detection_tips="Sysmon Event ID 10 (ProcessAccess к lsass.exe с масками PROCESS_VM_READ), аудит чтения ключей реестра HKLM\\SAM.",
            remediation="Включение защиты Windows Defender Credential Guard (LSA Protection / RunAsPPL), аудит SeDebugPrivilege."
        )

    def run_simulation(self) -> tuple[AttackStatus, str, str, str]:
        if platform.system() != "Windows":
            return AttackStatus.ERROR, "N/A", "", "Техника поддерживается только для ОС Windows"

        cmd = "reg query HKLM\\SAM & powershell -Command \"Get-Process lsass\""
        try:
            # 1. Проверяем, включен ли RunAsPPL (LSA Protection)
            ppl_enabled = False
            if winreg:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", 0, winreg.KEY_READ)
                    val, _ = winreg.QueryValueEx(key, "RunAsPPL")
                    if val in (1, 2):
                        ppl_enabled = True
                    winreg.CloseKey(key)
                except Exception:
                    pass

            # 2. Проверяем, заблокирован ли прямой доступ непривилегированного пользователя к ветке HKLM\SAM
            sam_accessible = False
            sam_res = subprocess.run("reg query HKLM\\SAM", shell=True, capture_output=True, text=True, timeout=5)
            if "ОШИБКА: Отказано в доступе" not in sam_res.stderr and "ERROR: Access is denied" not in sam_res.stderr and sam_res.returncode == 0:
                sam_accessible = True

            output_lines = [
                f"Защита процесса LSASS (RunAsPPL): {'ВКЛЮЧЕНА (LSA Protection активна)' if ppl_enabled else 'ОТКЛЮЧЕНА (Память LSASS потенциально уязвима для дампа Mimikatz/ProcDump)'}",
                f"Прямой доступ к ветке реестра SAM: {'ДОСТУПЕН (Критическая уязвимость!)' if sam_accessible else 'ЗАБЛОКИРОВАН (Ограничение прав действует)'}"
            ]

            if not ppl_enabled or sam_accessible:
                output_lines.append("ВЕРДИКТ: Хост уязвим к техникам дампа учетных записей (T1003) из-за отсутствия LSA Protection или избыточных прав.")
                return AttackStatus.VULNERABLE, cmd, "\n".join(output_lines), sam_res.stderr
            else:
                output_lines.append("ВЕРДИКТ: Базовая защита от извлечения учетных записей активна.")
                return AttackStatus.PROTECTED, cmd, "\n".join(output_lines), ""

        except Exception as e:
            return AttackStatus.ERROR, cmd, "", str(e)

    def cleanup(self) -> tuple[bool, str]:
        return True, "Тест проводился без изменения конфигурации и без создания дампа памяти"
