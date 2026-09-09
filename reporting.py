"""Portable assessment reports with observed data kept separate from interpretation."""
import json
import re


def markdown_text(value):
    text = str(value).replace('\n', ' ').replace('\r', ' ')
    return re.sub(r'([\\`*_{}\[\]()<>#+.!|~-])', r'\\\1', text)


def markdown_report(result, scan_id):
    lines = ['# SentinelAI assessment report', '',
             f'Assessment ID: {scan_id}', '',
             'Type: ' + markdown_text(result.get('scan_type', 'website')), '',
             'Target: ' + markdown_text(result['target']), '',
             'Recorded: ' + markdown_text(result.get('scanned_at', 'Not recorded in this legacy result')), '',
             '## Assessment limits', '',
             'This report records automated observations. It does not establish exploitability or certify security. '
             'The website score, when present, is a header checklist score, not a comprehensive risk rating.', '',
             '## Interpretation and next steps', '']
    for finding in result.get('findings', []):
        lines.extend(['### ' + markdown_text(finding['name']), '',
                      markdown_text(finding['description']), '',
                      'Next step: ' + markdown_text(finding['remediation']), ''])
    evidence = json.dumps(result, ensure_ascii=False, indent=2)
    # Untrusted DNS/header values cannot close the fenced evidence block.
    runs = re.findall(r'`+', evidence)
    fence = '`' * max(3, 1 + max((len(x) for x in runs), default=0))
    lines.extend(['## Recorded evidence', '', fence + 'json', evidence, fence, ''])
    return '\n'.join(lines)
