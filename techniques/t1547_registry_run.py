"""
T1547.001: Boot or Logon Autostart Execution: Registry Run Keys
Тактика: Persistence (TA0003)
"""

import platform
from core.base_technique import BaseTechnique
from core.models import TechniqueMeta, Tactic, Severity, AttackStatus

if platform.system() == "Windows":
    import winreg
else:
    winreg = None


class T1547RegistryRun(BaseTechnique):
    KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
    ENTRY_NAME = "MitreBasCanary_TestEntry"
    ENTRY_VALUE = r"C:\Windows\System32\cmd.exe /c echo canary_test"

    def get_meta(self) -> TechniqueMeta:
        return TechniqueMeta(
            technique_id="T1547.001",
            name="Registry Run Keys (Закрепление через автозагрузку в реестре)",
            tactic=Tactic.PERSISTENCE,
            description="Злоумышленники прописывают запуск вредоносных программ в ветку реестра CurrentVersion\\Run для автоматического запуска при входе пользователя.",
            severity=Severity.HIGH,
            mitre_url="https://attack.mitre.org/techniques/T1547/001/",
            mitre_detection_tips="Sysmon Event ID 12, 13 (RegistryEvent: Object create and delete, Value Set). Аудит изменений веток Run/RunOnce.",
            remediation="Блокировка неавторизованной модификации веток автозапуска средствами антивируса / EDR, контроль целостности реестра."
        )

    def run_simulation(self) -> tuple[AttackStatus, str, str, str]:
        if platform.system() != "Windows" or not winreg:
            return AttackStatus.ERROR, "N/A", "", "Техника поддерживается только для ОС Windows"

        cmd = f'reg add "HKCU\\{self.KEY_PATH}" /v {self.ENTRY_NAME} /t REG_SZ /d "{self.ENTRY_VALUE}" /f'
        try:
            # Открываем ключ реестра текущего пользователя
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.KEY_PATH, 0, winreg.KEY_SET_VALUE | winreg.KEY_READ)
            winreg.SetValueEx(key, self.ENTRY_NAME, 0, winreg.REG_SZ, self.ENTRY_VALUE)
            
            # Проверяем, записалось ли значение
            val, _ = winreg.QueryValueEx(key, self.ENTRY_NAME)
            winreg.CloseKey(key)

            if val == self.ENTRY_VALUE:
                return (
                    AttackStatus.VULNERABLE,
                    cmd,
                    f"Успешно создана запись автозапуска: HKCU\\{self.KEY_PATH}\\{self.ENTRY_NAME}",
                    ""
                )
            else:
                return AttackStatus.PROTECTED, cmd, "", "Значение не было записано"
        except PermissionError as pe:
            return AttackStatus.PROTECTED, cmd, "", f"Доступ заблокирован СЗИ/политикой: {pe}"
        except Exception as e:
            return AttackStatus.ERROR, cmd, "", str(e)

    def cleanup(self) -> tuple[bool, str]:
        if platform.system() != "Windows" or not winreg:
            return True, "Пропуск зачистки (не Windows)"

        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.KEY_PATH, 0, winreg.KEY_SET_VALUE)
            try:
                winreg.DeleteValue(key, self.ENTRY_NAME)
                winreg.CloseKey(key)
                return True, f"Запись {self.ENTRY_NAME} успешно удалена из автозапуска"
            except FileNotFoundError:
                winreg.CloseKey(key)
                return True, "Тестовая запись уже отсутствует"
        except Exception as e:
            return False, f"Ошибка зачистки ключа реестра: {e}"
