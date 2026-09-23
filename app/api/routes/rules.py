"""Detection rule endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from app.api import converters, schemas
from app.api.dependencies import RulesDep

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("", response_model=list[schemas.RuleOut])
def list_rules(rules: RulesDep) -> list[schemas.RuleOut]:
    return [converters.rule(r) for r in rules.rules]


@router.get("/{rule_id}", response_model=schemas.RuleOut)
def get_rule(rule_id: str, rules: RulesDep) -> schemas.RuleOut:
    rule = rules.by_id.get(rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="rule not found")
    return converters.rule(rule)
