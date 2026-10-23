"""Live Attack Simulation and Anomaly Stream API Endpoints."""
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.schemas import (
    SimulationScenarioMeta,
    SimulationLaunchRequest,
    SimulationLaunchResponse,
    SimulationStatusResponse,
    SimulationStartRequest,
)
from app.services.simulator import simulator

router = APIRouter(prefix="/simulation", tags=["Attack Simulator"])


@router.get("/scenarios", response_model=List[SimulationScenarioMeta])
def get_simulation_scenarios():
    """Returns available attack scenarios and metadata for live simulation."""
    return simulator.get_scenarios()


@router.post("/launch", response_model=SimulationLaunchResponse)
def launch_simulation(req: SimulationLaunchRequest, db: Session = Depends(get_db)):
    """
    Executes a real-time attack simulation burst against the live Spork-IDS detection engine.
    Generates realistic log events, evaluates bucket rules, and triggers real alerts and IP bans.
    All events and alerts are marked as [SIMULATED].
    """
    result = simulator.launch_attack_simulation(
        db=db,
        scenario_name=req.scenario,
        source_ip=req.source_ip,
        count=req.count,
    )
    return SimulationLaunchResponse(**result)


@router.post("/start", response_model=SimulationStatusResponse)
def start_simulation(req: SimulationStartRequest):
    """Starts the continuous background traffic & attack generator."""
    simulator.start_background_simulation(
        interval_seconds=req.interval_seconds,
        include_attacks=req.include_attacks,
    )
    return SimulationStatusResponse(**simulator.get_status())


@router.post("/stop", response_model=SimulationStatusResponse)
def stop_simulation():
    """Stops the continuous background traffic & attack generator."""
    simulator.stop_background_simulation()
    return SimulationStatusResponse(**simulator.get_status())


@router.get("/status", response_model=SimulationStatusResponse)
def get_simulation_status():
    """Returns the current status of the background simulation generator."""
    return SimulationStatusResponse(**simulator.get_status())


@router.post("/reset")
def reset_simulation(db: Session = Depends(get_db)):
    """Purges all simulated events, alerts, and decisions from the system."""
    return simulator.reset_simulated_data(db)
