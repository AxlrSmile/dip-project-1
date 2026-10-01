"""
Серверное веб-приложение FastAPI для управления симуляциями атак
"""

import os
import platform
import socket
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request

from core.engine import SimulationEngine
from core.reporter import ReportGenerator

app = FastAPI(title="MITRE ATT&CK BAS Platform API", version="1.0.0")

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Инициализируем синглтон движка симуляции
engine = SimulationEngine()
last_summary = None


@app.get("/", response_class=HTMLResponse)
async def read_dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/system-info")
async def get_system_info():
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "architecture": platform.architecture()[0],
        "processor": platform.processor()
    }


@app.get("/api/techniques")
async def list_techniques():
    return engine.get_available_techniques()


@app.post("/api/run/{technique_id}")
async def run_technique(technique_id: str):
    result = engine.run_single(technique_id)
    if not result:
        raise HTTPException(status_code=404, detail="Техника не найдена в реестре")
    return result


@app.post("/api/run-all")
async def run_all_audit():
    global last_summary
    last_summary = engine.run_all()
    return last_summary


@app.get("/api/report/html", response_class=HTMLResponse)
async def export_html_report():
    global last_summary
    if not last_summary:
        # Если отчет еще не запускался, запускаем симуляцию для генерации
        last_summary = engine.run_all()
    html_content = ReportGenerator.generate_html_report(last_summary)
    return HTMLResponse(content=html_content)


@app.get("/api/report/json")
async def export_json_report():
    global last_summary
    if not last_summary:
        last_summary = engine.run_all()
    return JSONResponse(content=last_summary.model_dump())
