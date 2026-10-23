"""Detection engine coordinating scenario rules, leaky buckets, and overflows."""
import time
import uuid
from typing import Dict, List, Tuple, Optional, Any, Union
from app.detection.buckets import LeakyBucket, TriggerBucket, UniqBucket
from app.detection.scenarios import BUILTIN_SCENARIOS, ScenarioDefinition


class OverflowEvent:
    """Represents an overflow detection outcome ready for alert and decision generation."""

    def __init__(
        self,
        scenario: ScenarioDefinition,
        source_ip: str,
        events_count: int,
        contributing_events: List[Dict[str, Any]],
        start_at_epoch: float,
        stop_at_epoch: float,
    ):
        self.scenario = scenario
        self.source_ip = source_ip
        self.events_count = events_count
        self.contributing_events = contributing_events
        self.start_at_epoch = start_at_epoch
        self.stop_at_epoch = stop_at_epoch


class DetectionEngine:
    """
    Central Detection Engine implementing CrowdSec-compatible scenario evaluation.
    Holds in-memory state of active bucket instances and coordinates overflow events.
    """

    def __init__(self):
        self.scenarios: Dict[str, ScenarioDefinition] = dict(BUILTIN_SCENARIOS)
        # Map of (scenario_name, stack_key) -> Bucket instance
        self.buckets: Dict[Tuple[str, str], Union[LeakyBucket, TriggerBucket, UniqBucket]] = {}
        # Scenario stats: scenario_name -> {"poured": int, "overflows": int, "last_overflow": Optional[float]}
        self.stats: Dict[str, Dict[str, Any]] = {
            name: {"poured": 0, "overflows": 0, "last_overflow": None}
            for name in self.scenarios
        }

    def _get_or_create_bucket(
        self, scenario: ScenarioDefinition, stack_key: str
    ) -> Union[LeakyBucket, TriggerBucket, UniqBucket]:
        key = (scenario.name, stack_key)
        if key not in self.buckets:
            if scenario.bucket_type == "trigger":
                self.buckets[key] = TriggerBucket(scenario.name, stack_key)
            elif scenario.bucket_type == "uniq":
                self.buckets[key] = UniqBucket(
                    scenario.name, stack_key, scenario.capacity, scenario.leakspeed_seconds
                )
            else:
                self.buckets[key] = LeakyBucket(
                    scenario.name, stack_key, scenario.capacity, scenario.leakspeed_seconds
                )
        return self.buckets[key]

    def process_event(self, event_dict: Dict[str, Any]) -> List[OverflowEvent]:
        """
        Evaluates a normalized event against all registered detection scenarios.
        Returns a list of OverflowEvents if any scenario triggers an overflow.
        """
        now = time.time()
        overflows: List[OverflowEvent] = []
        source_ip = event_dict.get("source_ip", "127.0.0.1")

        for name, scenario in self.scenarios.items():
            try:
                if not scenario.filter_fn(event_dict):
                    continue

                self.stats[name]["poured"] += 1
                bucket = self._get_or_create_bucket(scenario, source_ip)

                start_time = bucket.contributing_events[0].get("timestamp_epoch", now) if bucket.contributing_events else now

                event_summary = {
                    "source_ip": source_ip,
                    "service": event_dict.get("service"),
                    "action": event_dict.get("action"),
                    "raw_log": event_dict.get("raw_log", "")[:300],
                    "timestamp_epoch": now,
                    "meta_data": event_dict.get("meta_data", {}),
                }

                is_overflow = False
                count = 0

                if scenario.bucket_type == "uniq":
                    uniq_val = scenario.uniq_extractor(event_dict) if scenario.uniq_extractor else source_ip
                    is_overflow, count = bucket.pour(now, event_summary, uniq_val)
                else:
                    is_overflow, count = bucket.pour(now, event_summary)

                if is_overflow:
                    self.stats[name]["overflows"] += 1
                    self.stats[name]["last_overflow"] = now

                    overflow = OverflowEvent(
                        scenario=scenario,
                        source_ip=source_ip,
                        events_count=count,
                        contributing_events=list(bucket.contributing_events),
                        start_at_epoch=start_time,
                        stop_at_epoch=now,
                    )
                    overflows.append(overflow)

                    # Reset / destroy bucket instance after overflow
                    key = (scenario.name, source_ip)
                    if key in self.buckets:
                        del self.buckets[key]

            except Exception:
                # Shield engine from individual rule evaluation failures
                pass

        return overflows

    def evaluate_sandbox(
        self,
        scenario_name: str,
        source_ip: str,
        raw_log: str,
        service: Optional[str] = None,
        meta_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Executes an isolated simulation of a single scenario for live testing and UI demonstration.
        Does not mutate production bucket state.
        """
        if scenario_name not in self.scenarios:
            return {
                "matched_filter": False,
                "scenario_name": scenario_name,
                "bucket_type": "unknown",
                "current_count": 0,
                "capacity": 0,
                "overflow": False,
                "reason": f"Scenario {scenario_name} not found in registered scenarios",
            }

        scenario = self.scenarios[scenario_name]
        event_dict = {
            "source_ip": source_ip,
            "service": service or "unknown",
            "action": meta_data.get("action", "test_action") if meta_data else "test_action",
            "raw_log": raw_log,
            "meta_data": meta_data or {},
        }

        matched = scenario.filter_fn(event_dict)
        if not matched:
            return {
                "matched_filter": False,
                "scenario_name": scenario.name,
                "bucket_type": scenario.bucket_type,
                "current_count": 0,
                "capacity": scenario.capacity,
                "overflow": False,
                "reason": "Log event does not match scenario filter conditions.",
            }

        now = time.time()
        if scenario.bucket_type == "trigger":
            temp_bucket = TriggerBucket(scenario.name, source_ip)
            is_overflow, count = temp_bucket.pour(now, event_dict)
        elif scenario.bucket_type == "uniq":
            temp_bucket = UniqBucket(scenario.name, source_ip, scenario.capacity, scenario.leakspeed_seconds)
            val = scenario.uniq_extractor(event_dict) if scenario.uniq_extractor else "test_val"
            is_overflow, count = temp_bucket.pour(now, event_dict, val)
        else:
            temp_bucket = LeakyBucket(scenario.name, source_ip, scenario.capacity, scenario.leakspeed_seconds)
            is_overflow, count = temp_bucket.pour(now, event_dict)

        return {
            "matched_filter": True,
            "scenario_name": scenario.name,
            "bucket_type": scenario.bucket_type,
            "current_count": count,
            "capacity": scenario.capacity,
            "overflow": is_overflow,
            "reason": "Filter matched successfully. " + ("Overflow threshold reached!" if is_overflow else "Event poured into bucket."),
            "alert_generated": {
                "scenario": scenario.name,
                "severity": scenario.severity,
                "message": f"{scenario.description} ({source_ip})",
            } if is_overflow else None,
            "decision": {
                "type": scenario.remediation_type,
                "duration": scenario.remediation_duration,
                "value": source_ip,
            } if is_overflow else None,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Returns statistics of all scenarios and active bucket counts."""
        result = []
        for name, scenario in self.scenarios.items():
            active_count = sum(1 for (sc_name, _) in self.buckets if sc_name == name)
            stat = self.stats.get(name, {})
            result.append({
                "name": scenario.name,
                "description": scenario.description,
                "type": scenario.bucket_type,
                "capacity": scenario.capacity,
                "leakspeed": scenario.leakspeed_label,
                "poured_events": stat.get("poured", 0),
                "overflow_count": stat.get("overflows", 0),
                "active_buckets": active_count,
            })
        return {
            "total_active_buckets": len(self.buckets),
            "scenarios": result,
        }


# Singleton instance of DetectionEngine
engine = DetectionEngine()
