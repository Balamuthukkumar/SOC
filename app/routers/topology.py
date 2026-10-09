from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import func, select

from app.deps import DB, CurrentUser
from app.models import NetworkConnection
from app.schemas.common import ORM
from app.services.topology import CLEARTEXT_OT, build_graph

router = APIRouter()


class ConnIn(BaseModel):
    source_ip: str
    target_ip: str
    protocol: str
    port: int | None = None
    direction: str = "bidirectional"
    is_encrypted: bool = False
    bytes_transferred: int = 0


class ConnOut(ConnIn, ORM):
    id: int
    first_seen: datetime
    last_seen: datetime


@router.post("/connections", response_model=ConnOut, status_code=201)
async def add_connection(body: ConnIn, user: CurrentUser, db: DB):
    conn = NetworkConnection(user_id=user.id, **body.model_dump())
    db.add(conn)
    await db.commit()
    return conn


@router.post("/connections/batch", response_model=list[ConnOut], status_code=201)
async def add_connections(body: list[ConnIn], user: CurrentUser, db: DB):
    conns = [NetworkConnection(user_id=user.id, **c.model_dump()) for c in body[:1000]]
    db.add_all(conns)
    await db.commit()
    return conns


@router.get("/connections", response_model=list[ConnOut])
async def list_connections(user: CurrentUser, db: DB):
    return (await db.execute(select(NetworkConnection).where(NetworkConnection.user_id == user.id)
                             .order_by(NetworkConnection.last_seen.desc()).limit(1000))).scalars().all()


@router.get("/graph")
async def graph(user: CurrentUser, db: DB):
    return await build_graph(db, user.id)


@router.get("/stats")
async def stats(user: CurrentUser, db: DB):
    g = await build_graph(db, user.id)
    by_proto = dict((await db.execute(select(NetworkConnection.protocol, func.count()).where(
        NetworkConnection.user_id == user.id).group_by(NetworkConnection.protocol))).all())
    return {"total_nodes": len(g["nodes"]), "total_edges": len(g["edges"]), "connections_by_protocol": by_proto,
            "unencrypted_ot_connections": sum(e["risky"] for e in g["edges"]),
            "cleartext_protocols_watched": sorted(CLEARTEXT_OT)}
