"""
T1548.002: Abuse Elevation Control Mechanism: Bypass User Account Control
Тактика: Privilege Escalation (TA0004), Defense Evasion (TA0005)
"""

import subprocess
import platform
from core.base_technique import BaseTechnique
from core.models import TechniqueMeta, Tactic, Severity, AttackStatus

if platform.system() == "Windows":
    import winreg
else:
    winreg = None


class T1548UacBypassCheck(BaseTechnique):
    UAC_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    def get_meta(self) -> TechniqueMeta:
        return TechniqueMeta(
            technique_id="T1548.002",
            name="Bypass User Account Control (Анализ защищенности механизмов UAC)",
            tactic=Tactic.PRIVILEGE_ESCALATION,
            description="Злоумышленники используют слабые настройки UAC (например, ConsentPromptBehaviorAdmin = 5 без запроса пароля) для тихого повышения привилегий без ведома пользователя.",
            severity=Severity.HIGH,
            mitre_url="https://attack.mitre.org/techniques/T1548/002/",
            mitre_detection_tips="Sysmon Event ID 1 (создание высокопривилегированных процессов из родительских процессов со средним уровнем целостности).",
            remediation="Установка максимального уровня UAC (Всегда уведомлять), требование ввода учетных данных администратора при запросе повышения (ConsentPromptBehaviorAdmin = 1 или 2)."
        )

    def run_simulation(self) -> tuple[AttackStatus, str, str, str]:
        if platform.system() != "Windows":
            return AttackStatus.ERROR, "N/A", "", "Техника поддерживается только для ОС Windows"

        cmd = "whoami /priv & reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin"
        try:
            # 1. Запрос привилегий текущего токена
            priv_res = subprocess.run("whoami /priv", shell=True, capture_output=True, text=True, timeout=5)
            
            # 2. Проверка параметров UAC в реестре
            prompt_behavior = None
            enable_lua = None
            if winreg:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.UAC_KEY, 0, winreg.KEY_READ)
                    prompt_behavior, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
                    enable_lua, _ = winreg.QueryValueEx(key, "EnableLUA")
                    winreg.CloseKey(key)
                except Exception:
                    pass

            analysis_lines = [
                f"Статус службы UAC (EnableLUA): {'Включен (1)' if enable_lua == 1 else 'ОТКЛЮЧЕН (0)'}",
                f"Поведение запроса UAC (ConsentPromptBehaviorAdmin): {prompt_behavior}"
            ]

            # Если UAC отключен или установлен дефолтный режим (5 - elevate without prompt for binaries auto-elevating), хост потенциально подвержен UAC bypass
            if enable_lua == 0 or prompt_behavior == 5 or prompt_behavior == 0:
                analysis_lines.append("УЯЗВИМОСТЬ: Конфигурация UAC разрешает автоповышение без ввода пароля, возможен скрытый обход UAC через авто-элевацию (например, Fodhelper, Eventvwr, CMLua).")
                status = AttackStatus.VULNERABLE
            else:
                analysis_lines.append("ЗАЩИЩЕНО: UAC настроен в строгом режиме или требует подтверждения учетных данных.")
                status = AttackStatus.PROTECTED

            return status, cmd, "\n".join(analysis_lines) + "\n\nТекущие привилегии:\n" + priv_res.stdout[:500], priv_res.stderr
        except Exception as e:
            return AttackStatus.ERROR, cmd, "", str(e)

    def cleanup(self) -> tuple[bool, str]:
        return True, "Проверка только для чтения, изменения в реестр не вносились"
