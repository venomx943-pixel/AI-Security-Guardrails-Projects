import logging
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

# Configure structured enterprise logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname).4s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("AISecurity_SIEM_Dashboard")


@dataclass
class TelemetryEvent:
    """Represents a single security telemetry event ingested from the gateway pipeline."""
    timestamp: float
    event_id: str
    source_layer: str
    status: str  # "allowed" | "blocked" | "error"
    latency_ms: float
    threat_category: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SIEMMetricsSummary:
    """Aggregated security metrics for executive reporting and SOC monitoring."""
    total_requests: int
    total_blocked: int
    total_errors: int
    block_rate_percentage: float
    average_latency_ms: float
    active_threat_spikes: List[str] = field(default_factory=list)


class SecuritySIEMProcessor:
    """Centralized SIEM engine for real-time telemetry ingestion, aggregation, and anomaly detection."""
    
    def __init__(self, anomaly_threshold_count: int = 3):
        self.events: List[TelemetryEvent] = []
        self.anomaly_threshold = anomaly_threshold_count
        logger.info("Initialized AI Security SIEM Ingestion & Analytics Engine.")

    def ingest_event(self, event: TelemetryEvent) -> None:
        """Ingests a telemetry event from edge security proxies into the SIEM data lake."""
        self.events.append(event)
        if event.status == "blocked":
            logger.warning(f"SIEM Alert: Threat intercepted at [{event.source_layer}]. Category: {event.threat_category}")
        else:
            logger.info(f"SIEM Ingest: Event {event.event_id} processed successfully with status [{event.status}].")

    def _detect_anomalies(self) -> List[str]:
        """Analyzes ingested telemetry streams for sudden threat spikes or unusual error rates."""
        recent_blocks = [e for e in self.events if e.status == "blocked"]
        spikes = []
        
        if len(recent_blocks) >= self.anomaly_threshold:
            spikes.append(f"HIGH_THREAT_VELOCITY: {len(recent_blocks)} blocks detected within observation window.")
            
        error_events = [e for e in self.events if e.status == "error"]
        if len(error_events) > 0:
            spikes.append(f"PIPELINE_EXCEPTION_WARNING: {len(error_events)} infrastructural errors logged.")
            
        return spikes

    def generate_executive_dashboard_report(self) -> SIEMMetricsSummary:
        """Computes key performance indicators (KPIs) and risk metrics for executive dashboards."""
        total_reqs = len(self.events)
        if total_reqs == 0:
            return SIEMMetricsSummary(0, 0, 0, 0.0, 0.0, [])

        total_blks = sum(1 for e in self.events if e.status == "blocked")
        total_errs = sum(1 for e in self.events if e.status == "error")
        block_rate = (total_blks / total_reqs) * 100.0
        avg_latency = sum(e.latency_ms for e in self.events) / total_reqs
        spikes = self._detect_anomalies()

        return SIEMMetricsSummary(
            total_requests=total_reqs,
            total_blocked=total_blks,
            total_errors=total_errs,
            block_rate_percentage=round(block_rate, 2),
            average_latency_ms=round(avg_latency, 4),
            active_threat_spikes=spikes
        )


# SIEM Dashboard Execution Entrypoint 
if __name__ == "__main__":
    siem = SecuritySIEMProcessor(anomaly_threshold_count=2)

    # Simulating telemetry streams flowing in from the Enterprise Gateway (Project #9)
    print("--- Simulating SIEM Telemetry Ingestion Streams ---")
    
    siem.ingest_event(TelemetryEvent(
        timestamp=time.time(),
        event_id="EVT-1001",
        source_layer="InputSanitizationLayer",
        status="allowed",
        latency_ms=1.2401
    ))

    siem.ingest_event(TelemetryEvent(
        timestamp=time.time(),
        event_id="EVT-1002",
        source_layer="InputSanitizationLayer",
        status="blocked",
        latency_ms=2.1045,
        threat_category="Prompt Injection"
    ))

    siem.ingest_event(TelemetryEvent(
        timestamp=time.time(),
        event_id="EVT-1003",
        source_layer="ModelAlignmentLayer",
        status="blocked",
        latency_ms=4.8912,
        threat_category="Jailbreak / Malware Payload"
    ))

    # Generating the executive security dashboard summary
    print("\n--- Executive SOC Dashboard & SIEM Summary Report ---")
    report = siem.generate_executive_dashboard_report()
    
    print(f"Total Ingested Requests : {report.total_requests}")
    print(f"Total Blocked Threats   : {report.total_blocked}")
    print(f"Infrastructure Errors   : {report.total_errors}")
    print(f"Overall Block Rate      : {report.block_rate_percentage}%")
    print(f"Average Pipeline Latency: {report.average_latency_ms}ms")
    print(f"Active Threat Spikes    : {report.active_threat_spikes}")
    