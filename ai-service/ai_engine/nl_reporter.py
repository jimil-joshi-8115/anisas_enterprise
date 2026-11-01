"""Natural-language report generation.

Calls a real LLM API when a key is configured (OpenAI / Anthropic / Gemini /
Groq - REST only, no SDKs). Without a key it falls back to a deterministic
template engine and LABELS IT AS SUCH. The response always states the true
generation mode; it never claims GPT-4o without calling GPT.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import requests

log = logging.getLogger("anisas.ai.nl_reporter")

_TIMEOUT_S = 25


def _providers() -> List[tuple]:
    return [
        ("openai", "OPENAI_API_KEY", "gpt-4o-mini"),
        ("anthropic", "ANTHROPIC_API_KEY", "claude-3-5-haiku-latest"),
        ("gemini", "GEMINI_API_KEY", "gemini-2.0-flash"),
        ("groq", "GROQ_API_KEY", "openai/gpt-oss-120b"),
    ]


def _build_prompt(findings: Dict[str, Any]) -> str:
    return (
        "You are the reporting core of ANISAS, an enterprise network security "
        "platform. Write a concise executive security report from this JSON of "
        "verified scan findings. Rules: cite ONLY facts present in the JSON; if "
        "a data source was unavailable or a count is zero due to limited "
        "visibility, say so explicitly rather than claiming the host is clean. "
        "Return JSON with keys executiveSummary (<=120 words), keyThreats "
        "(array of 3 strings), actionPlan (array of 3 prioritized strings).\n\n"
        + str(findings)[:6000]
    )


def _call_openai(key: str, model: str, prompt: str) -> Optional[Dict[str, Any]]:
    r = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        json={"model": model, "temperature": 0.2,
              "messages": [{"role": "user", "content": prompt}],
              "response_format": {"type": "json_object"}},
        timeout=_TIMEOUT_S)
    r.raise_for_status()
    content = r.json()["choices"][0]["message"]["content"]
    import json as _json
    return _json.loads(content)


def _call_anthropic(key: str, model: str, prompt: str) -> Optional[Dict[str, Any]]:
    r = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                 "Content-Type": "application/json"},
        json={"model": model, "max_tokens": 900, "temperature": 0.2,
              "messages": [{"role": "user", "content": prompt}]},
        timeout=_TIMEOUT_S)
    r.raise_for_status()
    import json as _json
    text = "".join(b.get("text", "") for b in r.json()["content"])
    start, end = text.find("{"), text.rfind("}")
    return _json.loads(text[start:end + 1]) if start >= 0 else None


def _call_gemini(key: str, model: str, prompt: str) -> Optional[Dict[str, Any]]:
    r = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        params={"key": key},
        json={"contents": [{"parts": [{"text": prompt}]}],
              "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"}},
        timeout=_TIMEOUT_S)
    r.raise_for_status()
    import json as _json
    text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
    return _json.loads(text)


def _call_groq(key: str, model: str, prompt: str) -> Optional[Dict[str, Any]]:
    r = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        json={"model": model, "temperature": 0.2,
              "messages": [{"role": "user", "content": prompt}],
              "response_format": {"type": "json_object"}},
        timeout=_TIMEOUT_S)
    r.raise_for_status()
    import json as _json
    return _json.loads(r.json()["choices"][0]["message"]["content"])


_CALLERS = {"openai": _call_openai, "anthropic": _call_anthropic,
            "gemini": _call_gemini, "groq": _call_groq}


def template_fallback(findings: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic report built strictly from structured findings."""
    ip = findings.get("targetIp")
    dev = findings.get("deviceType") or "Unclassified host"
    os_ = findings.get("osFamily") or findings.get("predictedOs") or "unidentified OS"
    risk = findings.get("riskScore", 0)
    rating = findings.get("riskRating", "LOW")

    vis = findings.get("visibilityNote")
    summary = (
        f"ANISAS evaluated {ip}, classified as {dev} running {os_}. "
        f"Composite risk score is {risk}/100 ({rating})."
    )
    if vis:
        summary += f" Visibility limitation applies: {vis}"

    threats: List[str] = []
    for c in (findings.get("topCves") or [])[:2]:
        threats.append(f"CVE exposure {c.get('id')} (CVSS {c.get('cvss')}) on reachable service surface")
    for h in (findings.get("anomalies") or [])[:1]:
        threats.append(f"Subnet profile deviation at {h.get('ip')}: {h.get('interpretation')}")
    if not threats:
        threats.append("No confirmed threat indicators in available data sources")

    actions: List[str] = []
    if findings.get("weightedPorts"):
        actions.append("Restrict management and legacy service ports to administrative networks")
    if kev := findings.get("kevCount"):
        actions.append(f"Patch immediately: {kev} CISA-KEV listed vulnerability(ies) are exploitable now")
    if fw := (findings.get("firmwareDetail") or {}).get("monthsSinceRelease"):
        actions.append(f"Firmware is ~{fw} months old - verify current vendor release")
    actions.append("Re-run subnet sweep after changes to refresh anomaly baselines")
    return {
        "executiveSummary": summary,
        "keyThreats": threats[:3],
        "actionPlan": actions[:3],
    }


def generate(findings: Dict[str, Any]) -> Dict[str, Any]:
    for name, env_key, model in _providers():
        key = os.environ.get(env_key, "").strip()
        if not key:
            continue
        try:
            body = _CALLERS[name](key, model, _build_prompt(findings))
            if body and body.get("executiveSummary"):
                return {
                    **body,
                    "generationMode": "llm",
                    "llmModelUsed": f"{name}:{model}",
                    "llmStatus": "SYNTHESIS_COMPLETE",
                }
        except Exception as exc:  # noqa: BLE001
            log.warning("%s LLM call failed (%s); trying next provider", name, exc)

    fb = template_fallback(findings)
    fb.update({
        "generationMode": "template_fallback",
        "llmModelUsed": "ANISAS TemplateEngine-v1 (no LLM API key configured)",
        "llmStatus": "TEMPLATE_FALLBACK",
    })
    return fb
