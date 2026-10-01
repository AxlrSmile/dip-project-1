"""
Генератор отчетов по результатам эмуляции атак (core/reporter.py)
Формирует профессиональные отчеты в форматах HTML и JSON для пояснительной записки ВКР.
"""

import json
from core.models import RunSummary, AttackStatus


class ReportGenerator:
    @staticmethod
    def generate_html_report(summary: RunSummary) -> str:
        """
        Формирует презентабельный HTML-отчет в стиле SOC/Cybersecurity Audit Report.
        """
        score = summary.security_score
        if score >= 75:
            score_color = "#28a745"
            score_status = "ВЫСОКИЙ УРОВЕНЬ ЗАЩИЩЕННОСТИ"
        elif score >= 50:
            score_color = "#ffc107"
            score_status = "УМЕРЕННЫЙ УРОВЕНЬ РИСКА"
        else:
            score_color = "#dc3545"
            score_status = "КРИТИЧЕСКИЙ УРОВЕНЬ УЯЗВИМОСТИ"

        rows_html = ""
        for r in summary.results:
            if r.status == AttackStatus.VULNERABLE:
                badge = '<span class="badge bg-danger">УЯЗВИМО (Атака успешна)</span>'
            elif r.status == AttackStatus.PROTECTED:
                badge = '<span class="badge bg-success">ЗАЩИЩЕНО (СЗИ нейтрализовали)</span>'
            else:
                badge = '<span class="badge bg-secondary">ОШИБКА</span>'

            cleanup_badge = '<span class="text-success"><i class="bi bi-check-circle"></i> Зачищено</span>' if r.cleanup_success else '<span class="text-danger">Ошибка зачистки</span>'

            rows_html += f"""
            <tr>
                <td><strong>{r.technique_id}</strong></td>
                <td>{r.technique_name}</td>
                <td><small class="text-muted">{r.tactic}</small></td>
                <td>{badge}</td>
                <td>{r.execution_time_ms} мс</td>
                <td>{cleanup_badge}</td>
                <td><small>{r.remediation_advice}</small></td>
            </tr>
            """

        html_template = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Отчет по оценке защищенности | MITRE ATT&CK BAS Platform</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>
        body {{ background-color: #f8f9fa; font-family: 'Segoe UI', Roboto, sans-serif; }}
        .header-card {{ background: linear-gradient(135deg, #1a1e21, #0d6efd); color: white; border-radius: 12px; }}
        .score-circle {{ font-size: 3rem; font-weight: 800; color: {score_color}; }}
        .table-card {{ background: white; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }}
    </style>
</head>
<body class="py-4">
<div class="container">
    <div class="card header-card p-4 mb-4 shadow">
        <div class="row align-items-center">
            <div class="col-md-8">
                <h2 class="mb-1">Отчет по моделированию кибератак (BAS)</h2>
                <p class="mb-0 text-white-50">Оценка эффективности мер защиты на базе матрицы MITRE ATT&CK v14</p>
                <hr class="border-light opacity-25">
                <div class="row">
                    <div class="col-sm-6"><strong>Идентификатор запуска:</strong> {summary.run_id}</div>
                    <div class="col-sm-6"><strong>Дата и время:</strong> {summary.timestamp}</div>
                    <div class="col-sm-6"><strong>Целевой хост:</strong> {summary.target_host}</div>
                    <div class="col-sm-6"><strong>ОС:</strong> {summary.os_info}</div>
                </div>
            </div>
            <div class="col-md-4 text-center border-start border-light border-opacity-25">
                <div class="score-circle">{summary.security_score}%</div>
                <div class="fw-bold">{score_status}</div>
                <small class="text-white-50">Индекс сопротивляемости угрозам</small>
            </div>
        </div>
    </div>

    <div class="row mb-4">
        <div class="col-md-4">
            <div class="card text-center p-3 shadow-sm border-0 border-top border-primary border-4">
                <h5 class="text-muted">Всего проверено техник</h5>
                <h2 class="text-primary">{summary.total_executed}</h2>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card text-center p-3 shadow-sm border-0 border-top border-danger border-4">
                <h5 class="text-muted">Уязвимых техник (Прорыв)</h5>
                <h2 class="text-danger">{summary.vulnerable_count}</h2>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card text-center p-3 shadow-sm border-0 border-top border-success border-4">
                <h5 class="text-muted">Отражено средствами защиты</h5>
                <h2 class="text-success">{summary.protected_count}</h2>
            </div>
        </div>
    </div>

    <div class="card table-card p-4 mb-4">
        <h4 class="mb-3">Детализация проверки техник MITRE ATT&CK</h4>
        <div class="table-responsive">
            <table class="table table-hover align-middle">
                <thead class="table-light">
                    <tr>
                        <th>ID</th>
                        <th>Техника</th>
                        <th>Тактика</th>
                        <th>Вердикт</th>
                        <th>Время</th>
                        <th>Зачистка</th>
                        <th>Рекомендации по нейтрализации</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
    </div>

    <div class="card p-4 shadow-sm border-0">
        <h4>Заключение и рекомендации эксперта по ИБ</h4>
        <p>По результатам эмуляции атак выявлено <strong>{summary.vulnerable_count}</strong> неконтролируемых векторов внедрения и закрепления. Для нейтрализации рисков рекомендуется:</p>
        <ul>
            <li>Включить расширенную защиту подсистемы аутентификации LSA Protection (RunAsPPL) для блокировки T1003.</li>
            <li>Активировать строгий профиль UAC (ConsentPromptBehaviorAdmin = 2) с обязательным подтверждением паролем.</li>
            <li>Настроить аудит командной строки и событий PowerShell Script Block Logging (Event ID 4104) в SIEM.</li>
            <li>Ограничить возможность прямого сетевого egress-взаимодействия мимо корпоративных DNS-серверов.</li>
        </ul>
        <div class="text-muted text-end mt-3">
            <small>Сформировано автоматически программным комплексом MITRE BAS Platform (дипломный проект ВКР ИБ)</small>
        </div>
    </div>
</div>
</body>
</html>
"""
        return html_template

    @staticmethod
    def generate_json_report(summary: RunSummary) -> str:
        return summary.model_dump_json(indent=2)
