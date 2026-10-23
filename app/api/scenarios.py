"""Detection scenarios and live evaluation sandbox endpoints."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.schemas import (
    ScenarioListResponse,
    ScenarioInfo,
    ScenarioEvaluateRequest,
    ScenarioEvaluateResponse,
    SimulationLaunchRequest,
    SimulationLaunchResponse,
)
from app.detection.engine import engine as detection_engine
from app.services.simulator import simulator

router = APIRouter(prefix="/scenarios", tags=["Scenarios"])


@router.get("", response_model=ScenarioListResponse)
def list_scenarios():
    """Returns all supported detection scenarios and their live bucket statistics."""
    stats = detection_engine.get_stats()
    items = [
        ScenarioInfo(
            name=s["name"],
            description=s["description"],
            type=s["type"],
            capacity=s["capacity"],
            leakspeed=s["leakspeed"],
            filter_hint=f"Filter criteria for {s['name']}",
            poured_events=s["poured_events"],
            overflow_count=s["overflow_count"],
            active_buckets=s["active_buckets"],
        )
        for s in stats["scenarios"]
    ]
    return ScenarioListResponse(total=len(items), items=items)


@router.post("/evaluate", response_model=ScenarioEvaluateResponse)
def evaluate_scenario_sandbox(req: ScenarioEvaluateRequest):
    """
    Evaluates a test log line against a specific scenario in an isolated sandbox.
    Does not mutate production state or trigger real permanent database bans.
    Ideal for rule testing and dashboard demonstrations.
    """
    result = detection_engine.evaluate_sandbox(
        scenario_name=req.scenario_name,
        source_ip=req.source_ip,
        raw_log=req.raw_log,
        service=req.service,
        meta_data=req.meta_data,
    )
    return ScenarioEvaluateResponse(**result)


@router.post("/simulate", response_model=SimulationLaunchResponse)
def simulate_scenario(req: SimulationLaunchRequest, db: Session = Depends(get_db)):
    """
    Executes a real simulation burst against the live detection engine for this scenario.
    Generates logs, updates bucket stats, and produces real alerts/bans.
    """
    result = simulator.launch_attack_simulation(
        db=db,
        scenario_name=req.scenario,
        source_ip=req.source_ip,
        count=req.count,
    )
    return SimulationLaunchResponse(**result)

