"""
Базовый класс для всех техник эмуляции атак MITRE ATT&CK
Гарантирует безопасное выполнение и обязательную зачистку следов (Cleanup).
"""

from abc import ABC, abstractmethod
import time
from core.models import TechniqueMeta, ExecutionResult, AttackStatus


class BaseTechnique(ABC):
    """
    Абстрактный класс модуля эмуляции техники.
    Каждая реализация обязана иметь метод зачистки (cleanup),
    чтобы исключить нанесение ущерба тестовой системе.
    """

    def __init__(self):
        self.meta = self.get_meta()

    @abstractmethod
    def get_meta(self) -> TechniqueMeta:
        """Возвращает метаданные техники (ID, название, тактика, описание)."""
        pass

    @abstractmethod
    def run_simulation(self) -> tuple[AttackStatus, str, str, str]:
        """
        Основной метод симуляции атаки.
        Возвращает кортеж: (статус, выполненная команда, stdout, stderr)
        """
        pass

    @abstractmethod
    def cleanup(self) -> tuple[bool, str]:
        """
        Зачистка артефактов симуляции (удаление тестовых ключей реестра, канареечных файлов и т.д.)
        Возвращает: (успешно_ли, лог зачистки)
        """
        pass

    def verify_detection(self) -> tuple[bool, str]:
        """
        Проверка фиксации атаки средствами мониторинга ОС / СЗИ (Event Log, Sysmon).
        По умолчанию проверяется базовая регистрация событий.
        """
        return False, "СЗИ не зафиксировали событие в журнале аудита"

    def execute(self) -> ExecutionResult:
        """
        Полный жизненный цикл проверки:
        1. Запуск симуляции с замером времени
        2. Проверка детекта
        3. Зачистка следов
        4. Формирование отчета
        """
        start_time = time.perf_counter()
        status, cmd, out, err = self.run_simulation()
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Проверка фиксации
        detected, detection_info = self.verify_detection()
        if detected and status == AttackStatus.VULNERABLE:
            # Если атака выполнилась, но была задетектирована системой мониторинга
            status = AttackStatus.PROTECTED

        # Обязательная зачистка следов
        cleanup_success, cleanup_log = self.cleanup()

        return ExecutionResult(
            technique_id=self.meta.technique_id,
            technique_name=self.meta.name,
            tactic=self.meta.tactic.value,
            status=status,
            execution_time_ms=elapsed_ms,
            command_executed=cmd,
            stdout=out[:2000] if out else "",
            stderr=err[:2000] if err else "",
            cleanup_success=cleanup_success,
            cleanup_log=cleanup_log,
            detection_verified=detected,
            telemetry_source=detection_info,
            remediation_advice=self.meta.remediation
        )
