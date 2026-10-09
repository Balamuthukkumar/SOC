#!/usr/bin/env python3
"""Retroactively tag or delete demo/seed/simulated data in an existing database.

The `is_synthetic` column (added by migration 920d933cd2f6) defaults new rows to real (False) so nothing already
in the database silently disappears. Two things can leave real-looking rows behind from before that column (or
before a given script was updated to set it):

  1. `seed_demo()` — matched by exact content against app/seed.py's ALERTS, EVENTS and the demo case title.
  2. `scripts/simulate_attack.py` runs — matched by EventSource name (older runs predate its `synthetic: true`
     tagging). Every event from that sensor, any case built only from them, and the sensor row itself are swept.

Only rows belonging to the demo account (admin@example.com) are ever touched, and only rows matching one of the
above by content or by originating sensor. Nothing else in the database is read or written.

    python scripts/purge_demo_data.py            # tag matching rows is_synthetic=True (safe default)
    python scripts/purge_demo_data.py --delete    # permanently remove them instead
    python scripts/purge_demo_data.py --dry-run   # report what would happen, change nothing
"""
import argparse
import asyncio
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))  # repo root, for `app.*` — needed when imported, not just run directly
sys.path.insert(0, str(_HERE))         # scripts/ itself, for `import simulate_attack` below

from sqlalchemy import select  # noqa: E402

from app.db import SessionLocal  # noqa: E402
from app.models import Alert, Case, CaseAlert, CaseEvent, EventSource, RemediationAction, SecurityEvent, User
from app.seed import ALERTS, DEMO_EMAIL, EVENTS
from simulate_attack import SENSOR_NAME as SIMULATOR_SENSOR_NAME

TEST_TOOL_SENSOR_NAMES = {SIMULATOR_SENSOR_NAME}


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--delete", action="store_true", help="Remove matched rows instead of tagging them synthetic")
    ap.add_argument("--dry-run", action="store_true", help="Report matches only, change nothing")
    args = ap.parse_args()

    async with SessionLocal() as db:
        user = (await db.execute(select(User).where(User.email == DEMO_EMAIL))).scalar_one_or_none()
        if not user:
            print(f"No '{DEMO_EMAIL}' account found — nothing to do.")
            return 0

        # Match by exact content, not just "belongs to the demo user" — a real alert or event the demo
        # account later receives from a live feed/sensor must never be touched.
        alert_keys = {(cve, title) for _, cve, _, _, title in ALERTS}
        event_keys = {(sig, sip, dip, dport) for _, _, _, _, sig, sip, dip, dport, _, _ in EVENTS}
        demo_case_title = "Multi-Stage OT Intrusion: VPN Compromise -> Lateral Movement -> PLC Access Attempt"

        sim_sources = [s for s in (await db.execute(select(EventSource).where(
            EventSource.user_id == user.id, EventSource.name.in_(TEST_TOOL_SENSOR_NAMES)))).scalars()]
        sim_source_ids = {s.id for s in sim_sources}

        alerts = [a for a in (await db.execute(select(Alert).where(Alert.user_id == user.id))).scalars()
                  if (a.cve_id, a.title) in alert_keys]
        events = [e for e in (await db.execute(select(SecurityEvent).where(SecurityEvent.user_id == user.id))).scalars()
                  if (e.signature, e.source_ip, e.dest_ip, e.dest_port) in event_keys or e.source_id in sim_source_ids]
        matched_event_ids = {e.id for e in events}

        # A case is test/seed data when its title matches the demo case exactly, or when every event linked to
        # it is one we've already matched above (i.e. it was built entirely from test/seed telemetry).
        cases = []
        for c in (await db.execute(select(Case).where(Case.user_id == user.id))).scalars():
            if c.title == demo_case_title:
                cases.append(c)
                continue
            linked_event_ids = (await db.execute(select(CaseEvent.event_id).where(CaseEvent.case_id == c.id))).scalars().all()
            if linked_event_ids and set(linked_event_ids) <= matched_event_ids:
                cases.append(c)

        print(f"Found {len(alerts)} seeded alerts, {len(events)} test/seed events"
              f" ({len(sim_sources)} from simulator sensors), {len(cases)} test/seed case(s) for {DEMO_EMAIL}.")
        if args.dry_run:
            print("--dry-run: no changes made.")
            return 0
        if not (alerts or events or cases):
            print("Nothing to do — already clean (or already migrated with is_synthetic set at seed time).")
            return 0

        if args.delete:
            alert_ids = [a.id for a in alerts]
            event_ids = [e.id for e in events]
            for c in cases:
                await db.delete(c)  # cascades case_alerts / case_events / case_timeline for this case
            if alert_ids:
                await db.execute(CaseAlert.__table__.delete().where(CaseAlert.alert_id.in_(alert_ids)))
                await db.execute(RemediationAction.__table__.delete().where(RemediationAction.alert_id.in_(alert_ids)))
            if event_ids:
                await db.execute(CaseEvent.__table__.delete().where(CaseEvent.event_id.in_(event_ids)))
            for a in alerts:
                await db.delete(a)
            for e in events:
                await db.delete(e)
            for s in sim_sources:  # now empty of real children, delete the sensor row itself too
                await db.delete(s)
            await db.commit()
            print(f"Deleted {len(alerts)} alerts, {len(events)} events, {len(cases)} case(s), "
                  f"{len(sim_sources)} simulator sensor source(s).")
        else:
            for a in alerts:
                a.is_synthetic = True
            for e in events:
                e.is_synthetic = True
            for c in cases:
                c.is_synthetic = True
            await db.commit()
            print(f"Tagged {len(alerts)} alerts, {len(events)} events, {len(cases)} case(s) as is_synthetic=True.")
        print("These rows will no longer appear in /alerts/, /alerts/stats/overview, /events/, /events/stats, "
              "/cases/, MITRE coverage, or the dashboard.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
