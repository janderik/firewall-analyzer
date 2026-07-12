import json, argparse
from .models import Severity
from .parsers.iptables import IptablesParser
from .analyzer import RuleAnalyzer

def generate_report(result):
    findings = [{'line': f.rule_line, 'severity': f.severity.value, 'title': f.title, 'description': f.description, 'recommendation': f.recommendation} for f in result.findings]
    return json.dumps({'summary': {'total_rules': result.total_rules, 'allow_rules': result.allow_rules, 'deny_rules': result.deny_rules, 'findings': len(result.findings), 'critical': sum(1 for f in result.findings if f.severity == Severity.CRITICAL), 'high': sum(1 for f in result.findings if f.severity == Severity.HIGH)}, 'findings': findings}, indent=2)

def main():
    parser = argparse.ArgumentParser(description='Firewall Rule Analyzer')
    parser.add_argument('--file', '-f', required=True)
    parser.add_argument('--format', choices=['iptables'], default='iptables')
    parser.add_argument('--output', '-o', default=None)
    args = parser.parse_args()
    with open(args.file) as f:
        content = f.read()
    rules = IptablesParser().parse(content)
    print(f'[*] Parsed {len(rules)} rules')
    result = RuleAnalyzer().analyze(rules)
    print(f'[*] Found {len(result.findings)} findings')
    report = generate_report(result)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f'[+] Report saved to {args.output}')
    else:
        print(report)

if __name__ == '__main__':
    main()
