"""
Главная точка входа ПК «Атака-Тест» / MITRE ATT&CK BAS Platform
Поддерживает запуск в режиме веб-интерфейса и консольного аудита (CLI).
"""

import sys
import argparse
import webbrowser
import uvicorn
from core.engine import SimulationEngine
from core.reporter import ReportGenerator
from core.models import AttackStatus


def run_cli_mode():
    print("=" * 70)
    print("  ПК «АТАКА-ТЕСТ» | ЭМУЛЯЦИЯ КИБЕРАТАК ПО МАТРИЦЕ MITRE ATT&CK")
    print("  Дипломный проект по информационной безопасности")
    print("=" * 70)
    print("[*] Инициализация движка эмуляции атак...")

    engine = SimulationEngine()
    print(f"[*] Загружено доступных техник: {len(engine.techniques)}")
    print("[*] Запуск комплексного аудита хоста...\n")

    def on_step(res, current, total):
        status_symbol = "[+]" if res.status == AttackStatus.PROTECTED else "[-]"
        print(f"{status_symbol} ({current}/{total}) [{res.status.value}] {res.technique_id} - {res.technique_name}")
        print(f"    ↳ Зачистка: {res.cleanup_log}")

    summary = engine.run_all(on_step_callback=on_step)

    print("\n" + "=" * 70)
    print(f"  ИТОГОВЫЙ РЕЗУЛЬТАТ АУДИТА: {summary.security_score}% ЗАЩИЩЕННОСТИ")
    print("=" * 70)
    print(f"  • Всего проверено сценариев : {summary.total_executed}")
    print(f"  • Отражено средствами СЗИ   : {summary.protected_count}")
    print(f"  • Пропущено (Уязвимо)       : {summary.vulnerable_count}")
    print(f"  • Ошибок при тестировании   : {summary.error_count}")
    print("=" * 70)

    # Сохраняем локальный HTML отчет
    report_file = "diploma_audit_report.html"
    html_data = ReportGenerator.generate_html_report(summary)
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(html_data)
    print(f"[+] Итоговый отчет сохранен в файл: {report_file}")
    print("[+] Откройте его в браузере для включения графиков в пояснительную записку диплома.\n")


def run_web_mode(host: str = "127.0.0.1", port: int = 8000, auto_open: bool = True):
    print("=" * 70)
    print(f"  Запуск веб-панели управления: http://{host}:{port}")
    print("  Для выхода нажмите Ctrl+C")
    print("=" * 70)
    if auto_open:
        try:
            webbrowser.open(f"http://{host}:{port}")
        except Exception:
            pass
    uvicorn.run("web.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MITRE ATT&CK Breach & Attack Simulation Platform")
    parser.add_argument("--cli", action="store_true", help="Запустить аудит в консольном режиме без запуска веб-сервера")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Хост веб-сервера (по умолчанию 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Порт веб-сервера (по умолчанию 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Не открывать браузер автоматически")

    args = parser.parse_args()

    if args.cli:
        run_cli_mode()
    else:
        run_web_mode(host=args.host, port=args.port, auto_open=not args.no_browser)
