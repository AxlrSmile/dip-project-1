"""
Движок оркестрации симуляций (core/engine.py)
Управляет жизненным циклом запуска сценариев, сбором метрик и вычислением индекса защищенности.
"""

import platform
import socket
import uuid
from datetime import datetime
from typing import List, Optional, Callable
from core.models import RunSummary, ExecutionResult, AttackStatus
from core.base_technique import BaseTechnique
from techniques import get_all_technique_instances


class SimulationEngine:
    def __init__(self):
        self.techniques = get_all_technique_instances()
        self.history: List[RunSummary] = []

    def get_available_techniques(self) -> List[dict]:
        """Возвращает список доступных для проверки техник."""
        return [
            {
                "id": t.meta.technique_id,
                "name": t.meta.name,
                "tactic": t.meta.tactic.value,
                "severity": t.meta.severity.value,
                "description": t.meta.description,
                "mitre_url": t.meta.mitre_url,
                "remediation": t.meta.remediation
            }
            for t in self.techniques
        ]

    def run_single(self, technique_id: str) -> Optional[ExecutionResult]:
        """Запуск одной конкретной техники по ID."""
        for t in self.techniques:
            if t.meta.technique_id.lower() == technique_id.lower():
                return t.execute()
        return None

    def run_all(self, on_step_callback: Optional[Callable[[ExecutionResult, int, int], None]] = None) -> RunSummary:
        """
        Запуск полного комплексного аудита хоста по всем техникам MITRE ATT&CK.
        """
        run_id = f"RUN-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
        results: List[ExecutionResult] = []

        total = len(self.techniques)
        for idx, technique in enumerate(self.techniques):
            res = technique.execute()
            results.append(res)
            if on_step_callback:
                on_step_callback(res, idx + 1, total)

        vulnerable = sum(1 for r in results if r.status == AttackStatus.VULNERABLE)
        protected = sum(1 for r in results if r.status == AttackStatus.PROTECTED)
        errors = sum(1 for r in results if r.status == AttackStatus.ERROR)

        evaluable = vulnerable + protected
        if evaluable > 0:
            security_score = round((protected / evaluable) * 100.0, 1)
        else:
            security_score = 0.0

        summary = RunSummary(
            run_id=run_id,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target_host=socket.gethostname(),
            os_info=f"{platform.system()} {platform.release()} ({platform.architecture()[0]})",
            total_executed=len(results),
            vulnerable_count=vulnerable,
            protected_count=protected,
            error_count=errors,
            security_score=security_score,
            results=results
        )

        self.history.append(summary)
        return summary
