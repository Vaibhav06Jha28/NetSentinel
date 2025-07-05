from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
import json
import asyncio
from app.store import packet_data, anomaly_alerts, live_packet_queue

router = APIRouter()

# ✅ Maintain list of connected WebSocket connections
active_connections = {}

@router.websocket("/ws/packets")
async def websocket_endpoint(websocket: WebSocket, username: str = Query("Anonymous")):
    await websocket.accept()
    active_connections[websocket] = username
    print(f"👤 {username} connected via WebSocket")

    try:
        while True:
            if live_packet_queue:
                data = live_packet_queue[-1]
                # Optionally tag the message with who it's going to (for debugging)
                await websocket.send_json(data)
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        print(f"❌ {username} disconnected")
    except Exception as e:
        print(f"[WebSocket Error] {username}: {e}")
    finally:
        if websocket in active_connections:
            del active_connections[websocket]

# ✅ Async function to push a packet to all connected clients
async def push_packet_to_clients(packet: dict):
    message = json.dumps(packet)
    for ws, username in list(active_connections.items()):
        try:
            await ws.send_text(message)
        except Exception as e:
            print(f"[Push Packet Error to {username}]: {e}")

