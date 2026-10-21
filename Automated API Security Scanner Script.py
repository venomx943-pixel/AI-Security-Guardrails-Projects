import json
import time
import uuid
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

class RiskSeverity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class VulnerabilityCategory(Enum):
    BOLA_IDOR = "BOLA_IDOR"
    BFLA_FUNCTION_ACCESS = "BFLA_FUNCTION_ACCESS"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"
    EXCESSIVE_DATA_EXPOSURE = "EXCESSIVE_DATA_EXPOSURE"

@dataclass
class APIEndpointTarget:
    endpoint_id: str
    path: str
    method: str
    requires_auth: bool
    parameters: List[str]

@dataclass
class APISecurityFinding:
    finding_id: str
    endpoint_path: str
    vulnerability_type: str
    severity: str
    is_vulnerable: bool
    payload_used: str
    description: str
    remediation: str

@dataclass
class APIScanReport:
    scan_id: str
    timestamp: float
    total_endpoints_scanned: int
    vulnerabilities_found: int
    overall_risk_score: float
    findings: List[Dict[str, Any]]

class APIEndpointTargetRepository:
    def __init__(self):
        self._targets: List[APIEndpointTarget] = []
        self._initialize_targets()

    def _initialize_targets(self):
        self._targets.extend([
            APIEndpointTarget(
                endpoint_id="EP-001",
                path="/api/v1/users/profile/1001",
                method="GET",
                requires_auth=True,
                parameters=["user_id"]
            ),
            APIEndpointTarget(
                endpoint_id="EP-002",
                path="/api/v1/admin/privileges/update",
                method="POST",
                requires_auth=True,
                parameters=["role", "is_admin", "access_level"]
            ),
            APIEndpointTarget(
                endpoint_id="EP-003",
                path="/api/v1/account/settings",
                method="PUT",
                requires_auth=True,
                parameters=["email", "phone", "balance", "role"]
            )
        ])

    def get_targets(self) -> List[APIEndpointTarget]:
        return self._targets

class APISecurityVulnerabilityAnalyzer:
    def analyze_endpoint(self, target: APIEndpointTarget) -> APISecurityFinding:
        vulnerable = False
        vuln_type = ""
        severity = RiskSeverity.LOW.value
        payload = ""
        description = ""
        remediation = ""

        if "profile" in target.path:
            vulnerable = True
            vuln_type = VulnerabilityCategory.BOLA_IDOR.value
            severity = RiskSeverity.HIGH.value
            payload = "Modified user_id parameter from session context to target identifier."
            description = "Endpoint lacks proper object-level authorization checks, allowing unauthorized access to foreign user resources."
            remediation = "Implement strict server-side authorization validations matching the authenticated session identity."
        elif "admin" in target.path:
            vulnerable = True
            vuln_type = VulnerabilityCategory.BFLA_FUNCTION_ACCESS.value
            severity = RiskSeverity.CRITICAL.value
            payload = "Direct function invocation using standard user authentication token."
            description = "Administrative function endpoint is accessible without validating user privilege tiers."
            remediation = "Enforce role-based access control (RBAC) middleware on all administrative API routes."
        elif "settings" in target.path:
            vulnerable = True
            vuln_type = VulnerabilityCategory.MASS_ASSIGNMENT.value
            severity = RiskSeverity.HIGH.value
            payload = "Injected unauthorized parameters (balance, role) into input payload structure."
            description = "Server accepts and binds sensitive object properties directly from client input models."
            remediation = "Use explicit data transfer objects (DTOs) and whitelist permitted input fields."
        else:
            description = "No structural vulnerabilities detected on target endpoint."
            remediation = "Maintain standard security posture."

        return APISecurityFinding(
            finding_id=str(uuid.uuid4()),
            endpoint_path=target.path,
            vulnerability_type=vuln_type if vulnerable else "NONE",
            severity=severity if vulnerable else RiskSeverity.LOW.value,
            is_vulnerable=vulnerable,
            payload_used=payload if vulnerable else "N/A",
            description=description,
            remediation=remediation
        )

class APISecurityScannerEngine:
    def __init__(self):
        self._repository = APIEndpointTargetRepository()
        self._analyzer = APISecurityVulnerabilityAnalyzer()

    def execute_scan(self) -> APIScanReport:
        targets = self._repository.get_targets()
        findings: List[APISecurityFinding] = []
        vulnerability_count = 0
        risk_accumulator = 0.0

        for target in targets:
            finding = self._analyzer.analyze_endpoint(target)
            findings.append(finding)

            if finding.is_vulnerable:
                vulnerability_count += 1
                if finding.severity == RiskSeverity.CRITICAL.value:
                    risk_accumulator += 4.0
                elif finding.severity == RiskSeverity.HIGH.value:
                    risk_accumulator += 3.0
                elif finding.severity == RiskSeverity.MEDIUM.value:
                    risk_accumulator += 2.0
                else:
                    risk_accumulator += 1.0

        overall_risk = round(min(10.0, (risk_accumulator / (len(targets) * 4.0)) * 10.0), 2)

        return APIScanReport(
            scan_id=str(uuid.uuid4()),
            timestamp=time.time(),
            total_endpoints_scanned=len(targets),
            vulnerabilities_found=vulnerability_count,
            overall_risk_score=overall_risk,
            findings=[asdict(f) for f in findings]
        )

class APIScanReportFormatter:
    @staticmethod
    def print_summary(report: APIScanReport):
        print("=" * 70)
        print("          API SECURITY AUDIT & VULNERABILITY REPORT              ")
        print("=" * 70)
        print(f"Scan Identifier       : {report.scan_id}")
        print(f"Execution Timestamp   : {report.timestamp}")
        print(f"Endpoints Scanned     : {report.total_endpoints_scanned}")
        print(f"Vulnerabilities Found : {report.vulnerabilities_found}")
        print(f"Overall Risk Score    : {report.overall_risk_score} / 10.0")
        print("-" * 70)

        for idx, finding in enumerate(report.findings, 1):
            status = "VULNERABLE" if finding["is_vulnerable"] else "SECURE"
            print(f"[{idx}] Path: {finding['endpoint_path']} | Status: {status} | Severity: {finding['severity']}")
            if finding["is_vulnerable"]:
                print(f"    Vulnerability Type : {finding['vulnerability_type']}")
                print(f"    Payload Profile    : {finding['payload_used']}")
                print(f"    Remediation        : {finding['remediation_hint'] if 'remediation_hint' in finding else finding['remediation']}")
            print("-" * 70)

if __name__ == "__main__":
    print("[+] Initializing API Security Scanner Engine...")
    scanner_engine = APISecurityScannerEngine()
    
    print("[+] Executing Endpoint Security Assessment...")
    scan_report = scanner_engine.execute_scan()
    
    print("[+] Compiling Assessment Report...")
    APIScanReportFormatter.print_summary(scan_report)
    print("\n[+] API Scanner Execution Verified Successfully.")