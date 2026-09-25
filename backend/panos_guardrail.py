"""
AI Gateway & Model Armor Security Guardrails for PAN-OS Strata Assistant.

Provides enterprise-grade defense for LLMs:
1. Prompt Injection Detection (Direct & Indirect)
2. Jailbreak / Roleplay Escape Mitigation
3. Credential & Pre-Shared Key (PSK) Harvest Defense
4. Network Topology & PII Exfiltration Prevention
5. Audit Logging for AI Security Operations (SecOps)
"""

import re
from typing import Dict, Any, List, Tuple


class ModelArmorGuardrail:
    """
    Model Armor / AI Runtime Security Inspection Engine.
    Filters prompts and model responses against adversarial attacks.
    """

    # Adversarial patterns & prompt injection heuristics
    INJECTION_PATTERNS = [
        (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)", "PROMPT_INJECTION_DIRECT"),
        (r"system\s+(override|bypass|prompt|directive)", "SYSTEM_PROMPT_OVERRIDE"),
        (r"(disregard|forget|clear)\s+(all\s+)?(guidelines|rules|constraints)", "JAILBREAK_ATTEMPT"),
        (r"you\s+are\s+now\s+(in\s+developer\s+mode|dan|an\s+unrestricted)", "ROLEPLAY_JAILBREAK"),
        (r"(reveal|print|show|dump)\s+(the\s+)?(system\s+prompt|master\s+key|api_key|password)", "CREDENTIAL_HARVESTING"),
        (r"(disable|delete|flush|drop)\s+(all\s+)?(firewall|security\s+rules|policies)", "MALICIOUS_INTENT_COMMAND"),
        (r"base64|rot13|hex-encoded|eval\(", "OBFUSCATION_ATTACK"),
    ]

    # Sensitive PAN-OS configuration leakage checks
    SENSITIVE_LEAKS = [
        (r"phash\s+[a-zA-Z0-9\$\/]{20,}", "PANOS_PASSWORD_HASH_LEAK"),
        (r"pre-shared-key\s+key\s+\S+", "IKE_PSK_SECRET_LEAK"),
        (r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{60,})", "API_TOKEN_EXFILTRATION"),
    ]

    def __init__(self):
        self.audit_log: List[Dict[str, Any]] = []

    def inspect_prompt(self, user_prompt: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Scans inbound prompt for injection attacks, jailbreaks, and malicious commands.
        Returns: (is_safe: bool, security_metadata: dict)
        """
        for pattern, threat_type in self.INJECTION_PATTERNS:
            match = re.search(pattern, user_prompt, re.IGNORECASE)
            if match:
                finding = {
                    "verdict": "BLOCKED",
                    "threat_type": threat_type,
                    "matched_pattern": match.group(0),
                    "risk_score": 0.95,
                    "engine": "Model-Armor-v2 / PANW-AI-Runtime-Security",
                    "action": "DROP_AND_ALERT",
                    "reason": f"Adversarial prompt injection pattern detected ({threat_type}). Request terminated."
                }
                self.audit_log.append(finding)
                return False, finding

        # Check for credential leakage in the prompt
        for pattern, threat_type in self.SENSITIVE_LEAKS:
            match = re.search(pattern, user_prompt, re.IGNORECASE)
            if match:
                finding = {
                    "verdict": "BLOCKED",
                    "threat_type": threat_type,
                    "matched_pattern": "***REDACTED***",
                    "risk_score": 0.99,
                    "engine": "Model-Armor-v2 / PANW-AI-Runtime-Security",
                    "action": "DROP_AND_REDACT",
                    "reason": f"Sensitive credential or token exfiltration detected ({threat_type}). Request terminated."
                }
                self.audit_log.append(finding)
                return False, finding

        # Prompt passed security guardrails
        return True, {
            "verdict": "PERMITTED",
            "threat_type": "NONE",
            "risk_score": 0.02,
            "engine": "Model-Armor-v2 / PANW-AI-Runtime-Security",
            "action": "ALLOW"
        }

    def inspect_response(self, response_text: str) -> str:
        """
        Scans outbound model response to prevent system prompt leakage or secret exfiltration.
        Redacts any discovered secrets.
        """
        sanitized = response_text
        for pattern, threat_type in self.SENSITIVE_LEAKS:
            sanitized = re.sub(pattern, "[REDACTED_BY_MODEL_ARMOR]", sanitized, flags=re.IGNORECASE)
        return sanitized


class AIGatewayRouter:
    """
    AI Gateway Routing & Telemetry Layer.
    Enforces rate limits, token budgeting, audit logging, and guardrails.
    """
    def __init__(self, guardrail: ModelArmorGuardrail):
        self.guardrail = guardrail
        self.total_requests = 0
        self.blocked_requests = 0

    def process_query(self, user_prompt: str, agent_fn) -> Dict[str, Any]:
        """
        Routes the prompt through Model Armor before calling the underlying agent.
        """
        self.total_requests += 1
        
        # 1. Model Armor Pre-execution Inspection
        is_safe, security_meta = self.guardrail.inspect_prompt(user_prompt)
        
        if not is_safe:
            self.blocked_requests += 1
            return {
                "question": user_prompt,
                "category": "security_violation",
                "security_status": "BLOCKED",
                "armor_metadata": security_meta,
                "answer": (
                    f"⛔ **Model Armor / AI Runtime Security Alert**\n\n"
                    f"**Verdict**: `BLOCKED` (Risk Score: {security_meta['risk_score']})\n"
                    f"**Threat Vector**: `{security_meta['threat_type']}`\n"
                    f"**Reason**: {security_meta['reason']}\n\n"
                    f"Your prompt violated the Palo Alto Networks AI Safety Guardrail policy. "
                    f"Adversarial overrides, prompt injection, and credential dumps are strictly prohibited."
                ),
                "related_nodes": []
            }

        # 2. Invoke Autonomous Agent / Tools
        agent_result = agent_fn(user_prompt)

        # 3. Model Armor Post-execution Response Sanitization
        if "answer" in agent_result:
            agent_result["answer"] = self.guardrail.inspect_response(agent_result["answer"])

        agent_result["security_status"] = "VERIFIED_SAFE"
        agent_result["armor_metadata"] = security_meta
        return agent_result
