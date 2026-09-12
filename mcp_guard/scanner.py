"""Scanner engine for MCP Guard."""

from __future__ import annotations

from .models import MCPManifest, RiskFinding, ScanResult
from .rules import ALL_RULES, SecurityRule


class Scanner:
    """Scan MCP manifests for security risks."""

    def __init__(self, rules: list[SecurityRule] | None = None):
        """Initialize scanner with rules."""
        self.rules = rules or ALL_RULES

    def scan(self, manifest: MCPManifest) -> ScanResult:
        """Scan an MCP manifest and return findings."""
        all_findings: list[RiskFinding] = []

        for capability in manifest.capabilities:
            for rule in self.rules:
                findings = rule.check(capability, manifest)
                all_findings.extend(findings)

        return ScanResult(
            manifest=manifest,
            findings=all_findings,
        )

    def add_rule(self, rule: SecurityRule) -> None:
        """Add a custom rule to the scanner."""
        self.rules.append(rule)
