from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import DiscoveredDevice, NetworkConnection

CLEARTEXT_OT = {"modbus", "dnp3", "profibus", "ethernet_ip", "telnet", "ftp", "http"}


async def build_graph(db: AsyncSession, user_id: int) -> dict:
    conns = (await db.execute(select(NetworkConnection).where(NetworkConnection.user_id == user_id))).scalars().all()
    devices = (await db.execute(select(DiscoveredDevice).where(DiscoveredDevice.user_id == user_id))).scalars().all()
    nodes = {d.ip_address: {"id": d.ip_address, "label": d.hostname or d.manufacturer or d.ip_address,
                            "type": "ot_device" if d.is_ot_device else "device", "risk_score": d.risk_score or 0,
                            "device_id": d.id} for d in devices}
    for c in conns:
        for ip in (c.source_ip, c.target_ip):
            nodes.setdefault(ip, {"id": ip, "label": ip, "type": "unknown", "risk_score": 0, "device_id": None})
    edges = [{"source": c.source_ip, "target": c.target_ip, "protocol": c.protocol, "port": c.port,
              "is_encrypted": c.is_encrypted, "bytes_transferred": c.bytes_transferred,
              "risky": not c.is_encrypted and c.protocol.lower() in CLEARTEXT_OT} for c in conns]
    return {"nodes": list(nodes.values()), "edges": edges}
