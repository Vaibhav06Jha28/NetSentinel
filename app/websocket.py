from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
import json
from typing import Dict
from app.store import live_packet_queue

router = APIRouter()

# Store active connections
active_connections: Dict[str, WebSocket] = {}

@router.websocket("/ws/packets")
async def websocket_endpoint(websocket: WebSocket, username: str = Query("Anonymous")):
    await websocket.accept()
    active_connections[username] = websocket
    print(f"👤 {username} connected via WebSocket")

    try:
        while True:
            await websocket.receive_text()  # keep connection alive
    except WebSocketDisconnect:
        print(f"❌ {username} disconnected")
    except Exception as e:
        print(f"[WebSocket Error] {username}: {e}")
    finally:
        active_connections.pop(username, None)

# Push packets to all clients
async def push_packet_to_clients(packet: dict):
    message = json.dumps(packet)
    for username, ws in list(active_connections.items()):
        try:
            await ws.send_text(message)
        except Exception as e:
            print(f"[Push Packet Error to {username}]: {e}")
            active_connections.pop(username, None)
