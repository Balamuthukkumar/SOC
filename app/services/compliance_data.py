"""Control catalogues (reference data)."""

IEC_62443_CONTROLS = [
    {"control_id": "FR1-SR1.1", "title": "Human user identification and authentication", "category": "FR1 - Identification and Authentication"},
    {"control_id": "FR1-SR1.2", "title": "Software process identification and authentication", "category": "FR1 - Identification and Authentication"},
    {"control_id": "FR2-SR2.1", "title": "Authorization enforcement", "category": "FR2 - Use Control"},
    {"control_id": "FR3-SR3.1", "title": "Communication integrity", "category": "FR3 - System Integrity"},
    {"control_id": "FR3-SR3.3", "title": "Input validation", "category": "FR3 - System Integrity"},
    {"control_id": "FR4-SR4.1", "title": "Information confidentiality", "category": "FR4 - Data Confidentiality"},
    {"control_id": "FR5-SR5.1", "title": "Network segmentation", "category": "FR5 - Restricted Data Flow"},
    {"control_id": "FR5-SR5.2", "title": "Zone boundary protection", "category": "FR5 - Restricted Data Flow"},
    {"control_id": "FR6-SR6.1", "title": "Audit log accessibility", "category": "FR6 - Timely Response to Events"},
    {"control_id": "FR7-SR7.1", "title": "Denial of service protection", "category": "FR7 - Resource Availability"},
]

NIST_CSF_CONTROLS = [
    {"control_id": "ID.AM-1", "title": "Physical devices and systems inventoried", "category": "Identify - Asset Management"},
    {"control_id": "ID.AM-2", "title": "Software platforms and applications inventoried", "category": "Identify - Asset Management"},
    {"control_id": "ID.RA-1", "title": "Asset vulnerabilities identified and documented", "category": "Identify - Risk Assessment"},
    {"control_id": "PR.AC-5", "title": "Network integrity protected (segmentation, etc.)", "category": "Protect - Access Control"},
    {"control_id": "PR.DS-1", "title": "Data-at-rest is protected", "category": "Protect - Data Security"},
    {"control_id": "PR.IP-12", "title": "Vulnerability management plan developed and implemented", "category": "Protect - Protective Processes"},
    {"control_id": "DE.CM-1", "title": "Network is monitored to detect cybersecurity events", "category": "Detect - Continuous Monitoring"},
    {"control_id": "DE.CM-8", "title": "Vulnerability scans performed", "category": "Detect - Continuous Monitoring"},
    {"control_id": "RS.AN-1", "title": "Notifications from detection systems investigated", "category": "Respond - Analysis"},
    {"control_id": "RS.MI-2", "title": "Incidents are mitigated", "category": "Respond - Mitigation"},
    {"control_id": "RC.RP-1", "title": "Recovery plan executed during or after event", "category": "Recover - Recovery Planning"},
]
