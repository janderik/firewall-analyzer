from .models import AnalysisResult, Finding, Severity, Action

class RuleAnalyzer:
    def analyze(self, rules):
        result = AnalysisResult(total_rules=len(rules), rules=rules)
        result.allow_rules = sum(1 for r in rules if r.action == Action.ALLOW)
        result.deny_rules = len(rules) - result.allow_rules
        result.findings.extend(self._check_wildcard(rules))
        result.findings.extend(self._check_sensitive_ports(rules))
        result.findings.extend(self._check_any_any(rules))
        result.findings.extend(self._check_ssh(rules))
        result.findings.extend(self._check_empty(rules))
        return result
    def _check_wildcard(self, rules):
        return [Finding(r.line_number, Severity.HIGH, 'Wildcard source ALLOW', f'Allows from any source: {r.raw[:80]}', 'Restrict source IPs', 'network', 'CWE-284') for r in rules if r.action == Action.ALLOW and r.source in ('0.0.0.0/0', 'any', '::/0')]
    def _check_sensitive_ports(self, rules):
        return [Finding(r.line_number, Severity.CRITICAL, f'Port {r.destination_port} exposed', f'Sensitive port open: {r.raw[:80]}', 'Restrict access', 'network', 'CWE-284') for r in rules if r.action == Action.ALLOW and r.destination_port in ('22', '3389', '23', '21')]
    def _check_any_any(self, rules):
        return [Finding(r.line_number, Severity.CRITICAL, 'Allow all traffic', f'Permits everything: {r.raw[:80]}', 'Apply least privilege', 'network', 'CWE-284') for r in rules if r.action == Action.ALLOW and r.source in ('0.0.0.0/0', 'any') and r.destination_port is None]
    def _check_ssh(self, rules):
        return [Finding(r.line_number, Severity.CRITICAL, 'SSH exposed to internet', 'Port 22 open to all', 'Use VPN or restrict IPs', 'network', 'CWE-284') for r in rules if r.action == Action.ALLOW and r.destination_port == '22' and r.source in ('0.0.0.0/0', 'any')]
    def _check_empty(self, rules):
        return [Finding(0, Severity.HIGH, 'No rules defined', 'Firewall has no rules', 'Implement deny-all default')] if not rules else []
