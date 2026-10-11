"""AI triage: reason over Slither's evidence and return a validated, structured hypothesis."""

import json
import re

from pydantic import ValidationError

from slither.tools.workbench.ai.provider import AIProvider, AIProviderError
from slither.tools.workbench.models import AttackPath, Assessment, Exploitability, Finding

TRIAGE_IMPACTS = {"High", "Medium", "Low"}

SYSTEM_PROMPT = """You are a smart-contract security auditor triaging findings from the Slither
static analyzer. You receive one finding plus the evidence Slither extracted. Reason ONLY over that
evidence; do not invent functions, variables or lines that are not in it. You are producing a
hypothesis that will later be checked by dynamic tests, so be calibrated: say "unknown" rather than
guess.

Respond with a single JSON object and nothing else, using exactly these keys:
{
  "classification": one of "likely_exploitable", "possibly_exploitable",
                    "unlikely_exploitable", "likely_false_positive", "unknown",
  "confidence": integer 0-100 (confidence in the classification),
  "summary": one sentence,
  "why_it_matters": 1-3 sentences,
  "preconditions": [strings] conditions an attacker needs,
  "evidence": [strings] each citing a concrete fact from the provided evidence (file:line when known),
  "false_positive_indicators": [strings] facts suggesting this is not exploitable,
  "impact": 1-2 sentences,
  "remediation": concrete fix,
  "attack_steps": [strings] ordered candidate attack sequence, empty if not exploitable,
  "affected_state": [state variable names]
}"""

JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)


def needs_triage(finding: Finding) -> bool:
    return finding.impact in TRIAGE_IMPACTS and finding.evidence is not None


def build_prompt(finding: Finding, paths: list[AttackPath]) -> str:
    evidence = finding.evidence.model_dump(exclude={"source"}) if finding.evidence else None
    related_paths = [
        {"title": p.title, "steps": p.narrative, "derived_from": p.derived_from}
        for p in paths
        if finding.id in p.finding_ids
    ]
    payload = {
        "finding": {
            "detector": finding.detector,
            "title": finding.title,
            "severity": finding.impact,
            "detector_confidence": finding.confidence,
            "slither_description": finding.description,
            "location": finding.location.model_dump() if finding.location else None,
            "related_locations": [r.model_dump() for r in finding.related],
            "detector_documentation": finding.wiki_description,
        },
        "function_evidence": evidence,
        "static_attack_paths": related_paths,
    }
    return "Triage this finding.\n\n" + json.dumps(payload, indent=2)


def parse_assessment(text: str) -> Assessment:
    """Validate model output. Raises ValueError with a readable reason when it is unusable."""
    match = JSON_OBJECT.search(text or "")
    if not match:
        raise ValueError("response contained no JSON object")
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError as e:
        raise ValueError(f"response JSON is malformed: {e}")
    if not isinstance(data, dict):
        raise ValueError("response JSON is not an object")
    if data.get("classification") not in {e.value for e in Exploitability}:
        data["classification"] = Exploitability.UNKNOWN.value
    if isinstance(data.get("confidence"), (int, float)):
        data["confidence"] = max(0, min(100, int(data["confidence"])))
    allowed = set(Assessment.model_fields) - {"provider", "model", "raw_error"}
    try:
        return Assessment.model_validate({k: v for k, v in data.items() if k in allowed})
    except ValidationError as e:
        raise ValueError(f"response did not match schema: {e.error_count()} error(s)")


def assess(provider: AIProvider, finding: Finding, paths: list[AttackPath]) -> Assessment:
    prompt = build_prompt(finding, paths)
    last_error = ""
    for attempt in range(2):
        user = prompt if attempt == 0 else (
            f"{prompt}\n\nYour previous answer was rejected ({last_error}). "
            "Return only the JSON object."
        )
        try:
            assessment = parse_assessment(provider.complete(SYSTEM_PROMPT, user))
        except AIProviderError as e:
            last_error = str(e)
            break
        except ValueError as e:
            last_error = str(e)
            continue
        assessment.provider, assessment.model = provider.name, provider.model
        return assessment
    return Assessment(
        classification=Exploitability.UNKNOWN,
        provider=provider.name,
        model=provider.model,
        raw_error=f"AI assessment unavailable: {last_error}",
    )
