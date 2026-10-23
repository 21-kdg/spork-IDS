"""Decision management service handling active and historical bans/throttles."""
import uuid
import re
from datetime import datetime, timedelta
from typing import Optional, List
from sqlalchemy.orm import Session
from app.models.db_models import DecisionModel


def parse_duration_to_timedelta(duration_str: str) -> timedelta:
    """
    Parses duration strings like '30m', '1h', '4h', '24h', '7d' into python timedelta.
    Defaults to 4 hours if unrecognized.
    """
    duration = duration_str.strip().lower()
    match = re.match(r"^(\d+)\s*([smhdw])$", duration)
    if not match:
        return timedelta(hours=4)

    qty = int(match.group(1))
    unit = match.group(2)

    if unit == "s":
        return timedelta(seconds=qty)
    elif unit == "m":
        return timedelta(minutes=qty)
    elif unit == "h":
        return timedelta(hours=qty)
    elif unit == "d":
        return timedelta(days=qty)
    elif unit == "w":
        return timedelta(weeks=qty)

    return timedelta(hours=4)


class DecisionManager:
    """Manages active, expired, and manual remediation decisions."""

    @staticmethod
    def create_decision(
        db: Session,
        value: str,
        scope: str = "Ip",
        decision_type: str = "ban",
        duration: str = "4h",
        scenario: str = "manual/admin-ban",
        origin: str = "spork-ids",
        alert_id: Optional[int] = None,
        simulated: bool = False,
    ) -> DecisionModel:
        """Creates a new decision and persists it to the database."""
        delta = parse_duration_to_timedelta(duration)
        now = datetime.utcnow()
        until = now + delta

        decision = DecisionModel(
            uuid=str(uuid.uuid4()),
            alert_id=alert_id,
            origin=origin,
            type=decision_type,
            scope=scope,
            value=value,
            scenario=scenario,
            duration=duration,
            until=until,
            is_active=True,
            simulated=simulated,
            created_at=now,
        )
        db.add(decision)
        db.commit()
        db.refresh(decision)
        return decision

    @staticmethod
    def get_active_decisions(
        db: Session,
        scope: Optional[str] = None,
        decision_type: Optional[str] = None,
        value: Optional[str] = None,
    ) -> List[DecisionModel]:
        """Retrieves currently active unexpired decisions."""
        now = datetime.utcnow()
        query = db.query(DecisionModel).filter(
            DecisionModel.is_active == True,  # noqa: E712
            DecisionModel.until > now,
        )
        if scope:
            query = query.filter(DecisionModel.scope == scope)
        if decision_type:
            query = query.filter(DecisionModel.type == decision_type)
        if value:
            query = query.filter(DecisionModel.value == value)

        return query.order_by(DecisionModel.created_at.desc()).all()

    @staticmethod
    def is_value_banned(db: Session, value: str) -> bool:
        """Returns True if the IP, range, or username has an active ban decision."""
        now = datetime.utcnow()
        return (
            db.query(DecisionModel)
            .filter(
                DecisionModel.value == value,
                DecisionModel.type == "ban",
                DecisionModel.is_active == True,  # noqa: E712
                DecisionModel.until > now,
            )
            .first()
            is not None
        )

    @staticmethod
    def revoke_decision(db: Session, decision_id: int) -> bool:
        """Revokes (cancels) an active decision."""
        decision = db.query(DecisionModel).filter(DecisionModel.id == decision_id).first()
        if not decision:
            return False
        decision.is_active = False
        db.commit()
        return True


decision_manager = DecisionManager()
