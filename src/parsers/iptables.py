from ..models import FirewallRule, Action, Protocol

class IptablesParser:
    CHAINS = {'INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING'}
    def parse(self, rules_text):
        rules = []
        for i, line in enumerate(rules_text.strip().split('\n'), 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('*') or line.startswith(':'):
                continue
            rule = self._parse_line(line, i)
            if rule:
                rules.append(rule)
        return rules
    def _parse_line(self, line, num):
        rule = FirewallRule(line_number=num, raw=line)
        tokens = line.split()
        idx = 0
        if tokens[idx] in ('-A', '-I', '-D'):
            idx += 1
        if idx < len(tokens) and tokens[idx] in self.CHAINS:
            rule.chain = tokens[idx]
            idx += 1
        while idx < len(tokens):
            t = tokens[idx]
            if t == '-j' and idx + 1 < len(tokens):
                a = tokens[idx + 1].lower()
                rule.action = {'accept': Action.ALLOW, 'drop': Action.DROP, 'reject': Action.REJECT, 'log': Action.LOG}.get(a, Action.DENY)
                idx += 2
            elif t == '-p' and idx + 1 < len(tokens):
                rule.protocol = {'tcp': Protocol.TCP, 'udp': Protocol.UDP, 'icmp': Protocol.ICMP, 'all': Protocol.ANY}.get(tokens[idx + 1].lower(), Protocol.ANY)
                idx += 2
            elif t == '-s' and idx + 1 < len(tokens):
                rule.source = tokens[idx + 1]
                idx += 2
            elif t == '-d' and idx + 1 < len(tokens):
                rule.destination = tokens[idx + 1]
                idx += 2
            elif t == '--dport' and idx + 1 < len(tokens):
                rule.destination_port = tokens[idx + 1]
                idx += 2
            elif t == '--sport' and idx + 1 < len(tokens):
                rule.source_port = tokens[idx + 1]
                idx += 2
            elif t == '-m' and idx + 1 < len(tokens):
                if tokens[idx + 1] == 'comment' and idx + 3 < len(tokens) and tokens[idx + 2] == '--comment':
                    rule.comment = tokens[idx + 3].strip('\"')
                    idx += 4
                else:
                    idx += 2
            elif t in ('-f', '-y', '--syn'):
                rule.flags.append(t)
                idx += 1
            else:
                idx += 1
        return rule
