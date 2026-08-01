"""Simulation and detection routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import write_audit
from app.db import get_db
from app.deps import AnalystUser, CurrentUser
from app.detection import list_rules, run_detection
from app.models import Detection, SimulatedEvent
from app.schemas import (
    DetectionPublic,
    RulePublic,
    SimulateRequest,
    SimulateResponse,
    SimulatedEventPublic,
)
from app.simulator import generate_events

router = APIRouter(tags=["lab"])


def _client_ip(request: Request) -> str | None:
    if request.client:
        return request.client.host
    return None


@router.get("/rules", response_model=list[RulePublic])
def get_rules(_: CurrentUser) -> list[RulePublic]:
    return [
        RulePublic(
            rule_id=info.rule_id,
            name=info.name,
            description=info.description,
            severity=info.severity,
            mitre_technique=info.mitre_technique,
        )
        for info in list_rules()
    ]


@router.post(
    "/simulate",
    response_model=SimulateResponse,
    status_code=status.HTTP_201_CREATED,
)
def simulate_attack(
    payload: SimulateRequest,
    request: Request,
    user: AnalystUser,
    db: Annotated[Session, Depends(get_db)],
) -> SimulateResponse:
    generated = generate_events(payload.scenario, count=payload.count, seed=payload.seed)
    rows: list[SimulatedEvent] = []
    for item in generated:
        row = SimulatedEvent(
            scenario=item.scenario,
            event_type=item.event_type,
            source_ip=item.source_ip,
            dest_ip=item.dest_ip,
            dest_port=item.dest_port,
            protocol=item.protocol,
            summary=item.summary,
            is_malicious=item.is_malicious,
            created_by=user.id,
        )
        db.add(row)
        rows.append(row)
    db.commit()
    for row in rows:
        db.refresh(row)

    hits = run_detection(rows)
    detections: list[Detection] = []
    for hit in hits:
        det = Detection(
            event_id=hit.event_id,
            rule_id=hit.rule_id,
            rule_name=hit.rule_name,
            severity=hit.severity,
            message=hit.message,
            mitre_technique=hit.mitre_technique,
        )
        db.add(det)
        detections.append(det)
    db.commit()
    for det in detections:
        db.refresh(det)

    write_audit(
        db,
        action="lab.simulate",
        resource=f"scenario:{payload.scenario.value}",
        actor_user_id=user.id,
        detail=f"events={len(rows)} detections={len(detections)}",
        ip_address=_client_ip(request),
        success=True,
    )

    return SimulateResponse(
        scenario=payload.scenario,
        events_created=len(rows),
        detections_created=len(detections),
        events=rows,
        detections=detections,
    )


@router.get("/events", response_model=list[SimulatedEventPublic])
def list_events(
    _: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[SimulatedEvent]:
    stmt = select(SimulatedEvent).order_by(SimulatedEvent.id.desc()).limit(limit)
    return list(db.scalars(stmt).all())


@router.get("/detections", response_model=list[DetectionPublic])
def list_detections(
    _: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[Detection]:
    stmt = select(Detection).order_by(Detection.id.desc()).limit(limit)
    return list(db.scalars(stmt).all())
