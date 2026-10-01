"""
T1070.004: Indicator Removal on Host: File Deletion
Тактика: Defense Evasion (TA0005)
"""

import os
import tempfile
import time
from core.base_technique import BaseTechnique
from core.models import TechniqueMeta, Tactic, Severity, AttackStatus


class T1070IndicatorRemoval(BaseTechnique):
    def get_meta(self) -> TechniqueMeta:
        return TechniqueMeta(
            technique_id="T1070.004",
            name="Indicator Removal: File Deletion (Заметание следов: удаление файлов)",
            tactic=Tactic.DEFENSE_EVASION,
            description="Злоумышленники удаляют файлы полезной нагрузки, временные дампы и скрипты сразу после их выполнения для противодействия форензике и криминалистическому анализу.",
            severity=Severity.MEDIUM,
            mitre_url="https://attack.mitre.org/techniques/T1070/004/",
            mitre_detection_tips="Sysmon Event ID 23, 26 (FileDelete, FileDeleteDetected). Аудит массовых операций удаления файлов в служебных каталогах (Temp, AppData).",
            remediation="Настройка централизованной отправки журналов файловой системы в SIEM до момента затирания данных."
        )

    def run_simulation(self) -> tuple[AttackStatus, str, str, str]:
        temp_dir = tempfile.gettempdir()
        canary_file = os.path.join(temp_dir, "mitre_canary_dropper_artifact.tmp")
        
        try:
            # 1. Создаем тестовый файл дроппера
            with open(canary_file, "w", encoding="utf-8") as f:
                f.write("MITRE_ATTACK_SIMULATION_CANARY_PAYLOAD_TEST")
            
            time.sleep(0.1)

            # 2. Немедленно удаляем его (заметание следов)
            if os.path.exists(canary_file):
                os.remove(canary_file)

            if not os.path.exists(canary_file):
                return (
                    AttackStatus.VULNERABLE,
                    f"create_and_delete({canary_file})",
                    "Тестовый артефакт успешно создан и бесследно удален из Temp-директории без блокировки средствами EDR/File Integrity Monitoring.",
                    ""
                )
            else:
                return AttackStatus.PROTECTED, f"delete({canary_file})", "", "Файл заблокирован или зафиксирован СЗИ"
        except Exception as e:
            return AttackStatus.ERROR, f"file_ops({canary_file})", "", str(e)

    def cleanup(self) -> tuple[bool, str]:
        temp_dir = tempfile.gettempdir()
        canary_file = os.path.join(temp_dir, "mitre_canary_dropper_artifact.tmp")
        if os.path.exists(canary_file):
            try:
                os.remove(canary_file)
                return True, "Остаточный файл удален"
            except Exception as e:
                return False, f"Ошибка зачистки: {e}"
        return True, "Файловые артефакты отсутствуют"
