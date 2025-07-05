from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.store import packet_data, filters, anomaly_alerts
from app.ids import rules

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def is_external(ip):
    return not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."))


# ✅ Dashboard route
@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    filtered_data = apply_filters(packet_data)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "packets": filtered_data,
        "alerts": anomaly_alerts[-10:],  # limit alerts shown
        "rules": rules
    })


# ✅ Toggle TCP filter
@router.get("/toggle_tcp")
async def toggle_tcp():
    filters["tcp_only"] = not filters["tcp_only"]
    return {"tcp_only": filters["tcp_only"]}


# ✅ Toggle external IP filter
@router.get("/toggle_external")
async def toggle_external():
    filters["external_only"] = not filters["external_only"]
    return {"external_only": filters["external_only"]}


# ✅ Add IDS Rule
@router.post("/add_rule")
async def add_rule_endpoint(
    request: Request,
    field: str = Form(...),
    operator: str = Form(...),
    value: str = Form(...),
    message: str = Form(...)
):
    rules.append({
        "field": field,
        "operator": operator,
        "value": value,
        "message": message
    })

    filtered_data = apply_filters(packet_data)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "packets": filtered_data,
        "alerts": anomaly_alerts[-10:],
        "rules": rules
    })


# ✅ Delete IDS Rule by index
@router.post("/delete_rule/{rule_index}")
async def delete_rule_endpoint(rule_index: int, request: Request):
    if 0 <= rule_index < len(rules):
        rules.pop(rule_index)

    filtered_data = apply_filters(packet_data)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "packets": filtered_data,
        "alerts": anomaly_alerts[-10:],
        "rules": rules
    })


# ✅ Default filter state
filters = {
    "external_only": True,
    "tcp_only": False,
}


# ✅ Modular filter logic

def apply_filters(data):
    filtered = data
    if filters["external_only"]:
        filtered = [p for p in filtered if is_external(p.get("src", "")) and is_external(p.get("dst", ""))]
    if filters["tcp_only"]:
        filtered = [p for p in filtered if p.get("proto") == "TCP"]
    return filtered

