"""Security event ingestion and detection pipeline."""
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.models.db_models import EventModel, AlertModel
from app.services.parser import parse_log_line, ParsedEvent
from app.services.enrichment import enrich_ip
from app.detection.engine import engine as detection_engine, OverflowEvent
from app.services.decision_manager import decision_manager


class IngestionPipeline:
    """Coordinates parsing, enrichment, persistence, and detection for security events."""

    @staticmethod
    def process_raw_line(
        db: Session,
        raw_line: str,
        service_hint: Optional[str] = None,
        is_simulated: bool = False,
    ) -> Dict[str, Any]:
        """Processes a single raw log string through the full Spork-IDS security pipeline."""
        parsed: ParsedEvent = parse_log_line(raw_line, service_hint=service_hint)
        enrichment = enrich_ip(parsed.source_ip)

        # 1. Persist Event
        event_record = EventModel(
            timestamp=parsed.timestamp,
            source_ip=parsed.source_ip,
            service=parsed.service,
            action=parsed.action,
            raw_log=parsed.raw_log,
            is_suspicious=parsed.is_suspicious,
            is_simulated=is_simulated,
        )
        event_record.meta_data = parsed.meta_data
        event_record.enrichment = enrichment

        db.add(event_record)
        db.commit()
        db.refresh(event_record)

        # 2. Evaluate Detection Rules
        event_dict = {
            "id": event_record.id,
            "source_ip": parsed.source_ip,
            "service": parsed.service,
            "action": parsed.action,
            "raw_log": parsed.raw_log,
            "meta_data": parsed.meta_data,
            "enrichment": enrichment,
            "timestamp": parsed.timestamp,
            "is_simulated": is_simulated,
        }

        overflows: List[OverflowEvent] = detection_engine.process_event(event_dict)

        alerts_created = []
        decisions_created = []

        # 3. Handle Overflows (Alert + Decision Creation)
        for overflow in overflows:
            now = datetime.utcnow()
            alert_uuid = str(uuid.uuid4())
            scenario = overflow.scenario

            alert_record = AlertModel(
                uuid=alert_uuid,
                scenario=scenario.name,
                message=f"{scenario.description} ({overflow.source_ip})",
                severity=scenario.severity,
                source_ip=overflow.source_ip,
                source_scope="Ip",
                events_count=overflow.events_count,
                capacity=scenario.capacity,
                leakspeed=scenario.leakspeed_label,
                start_at=datetime.utcfromtimestamp(overflow.start_at_epoch),
                stop_at=datetime.utcfromtimestamp(overflow.stop_at_epoch),
                created_at=now,
                status="active",
                is_simulated=is_simulated,
            )
            alert_record.meta_data = {
                "contributing_events": overflow.contributing_events,
                "enrichment": enrichment,
                "is_simulated": is_simulated,
            }

            db.add(alert_record)
            db.commit()
            db.refresh(alert_record)
            alerts_created.append(alert_record)

            # Create Attached Decision
            decision = decision_manager.create_decision(
                db=db,
                value=overflow.source_ip,
                scope="Ip",
                decision_type=scenario.remediation_type,
                duration=scenario.remediation_duration,
                scenario=scenario.name,
                origin="spork-ids",
                alert_id=alert_record.id,
                simulated=is_simulated,
            )
            decisions_created.append(decision)

        return {
            "event_id": event_record.id,
            "source_ip": parsed.source_ip,
            "service": parsed.service,
            "action": parsed.action,
            "is_suspicious": parsed.is_suspicious,
            "is_simulated": is_simulated,
            "alerts_triggered": len(alerts_created),
            "decisions_created": len(decisions_created),
            "alerts": [
                {
                    "id": a.id,
                    "uuid": a.uuid,
                    "scenario": a.scenario,
                    "severity": a.severity,
                    "source_ip": a.source_ip,
                    "message": a.message,
                }
                for a in alerts_created
            ],
            "decisions": [
                {
                    "id": d.id,
                    "uuid": d.uuid,
                    "type": d.type,
                    "value": d.value,
                    "duration": d.duration,
                    "scenario": d.scenario,
                }
                for d in decisions_created
            ],
        }

    @staticmethod
    def process_batch_raw(
        db: Session, logs: List[str], service_hint: Optional[str] = None
    ) -> Dict[str, Any]:
        """Processes a batch of raw log lines."""
        total_alerts = 0
        total_decisions = 0
        details = []

        for line in logs:
            if not line.strip():
                continue
            res = IngestionPipeline.process_raw_line(db, line, service_hint)
            total_alerts += res["alerts_triggered"]
            total_decisions += res["decisions_created"]
            details.append(res)

        return {
            "processed_count": len(details),
            "alerts_triggered": total_alerts,
            "decisions_created": total_decisions,
            "details": details,
        }


pipeline = IngestionPipeline()
