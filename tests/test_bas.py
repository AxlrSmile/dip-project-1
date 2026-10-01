"""
Модульные тесты для проверки корректности работы движка эмуляции атак
"""

import unittest
from core.engine import SimulationEngine
from core.models import AttackStatus
from techniques.t1082_system_info import T1082SystemInfo
from techniques.t1070_indicator_removal import T1070IndicatorRemoval


class TestMitreBasPlatform(unittest.TestCase):
    def setUp(self):
        self.engine = SimulationEngine()

    def test_techniques_discovery(self):
        """Проверка загрузки списка всех доступных техник."""
        techniques = self.engine.get_available_techniques()
        self.assertGreaterEqual(len(techniques), 8, "Должно быть загружено не менее 8 техник")
        
        tech_ids = [t["id"] for t in techniques]
        self.assertIn("T1082", tech_ids)
        self.assertIn("T1547.001", tech_ids)
        self.assertIn("T1053.005", tech_ids)
        self.assertIn("T1003", tech_ids)

    def test_t1082_execution(self):
        """Проверка работы техники сбора информации о системе T1082."""
        technique = T1082SystemInfo()
        res = technique.execute()
        self.assertIn(res.status, [AttackStatus.VULNERABLE, AttackStatus.PROTECTED])
        self.assertTrue(res.cleanup_success, "Зачистка должна завершиться успешно")

    def test_cleanup_guarantee(self):
        """Проверка обязательного удаления артефактов на примере T1070."""
        technique = T1070IndicatorRemoval()
        res = technique.execute()
        self.assertTrue(res.cleanup_success, "Индикатор должен быть безопасно удален")


if __name__ == "__main__":
    unittest.main()
