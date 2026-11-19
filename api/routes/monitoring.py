from fastapi import APIRouter

from app.api.deps import CurrentUser, RequireAnalyst
from app.services.live_capture import capture_manager, list_interfaces

router = APIRouter(prefix="/api/monitoring", tags=["Live Monitoring"])


@router.get("/status")
def status(user: CurrentUser) -> dict:
    return capture_manager.status()


@router.get("/interfaces")
def interfaces(user: CurrentUser) -> dict:
    return {
        "interfaces": list_interfaces(),
        "available": capture_manager.status()["available"],
    }


@router.post("/start")
def start(
    user: RequireAnalyst,
    interface: str | None = None,
    bpf_filter: str | None = None,
) -> dict:
    return capture_manager.start(interface, bpf_filter)


@router.post("/stop")
def stop(user: RequireAnalyst) -> dict:
    return capture_manager.stop()
