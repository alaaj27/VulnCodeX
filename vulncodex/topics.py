"""Question topics: keyword rules applied to the question text, in order (first match wins).

These are the rules behind every per-topic number in the paper. A question that matches no rule is
"Other". The six "description topics" of the paper are DESCRIPTION_TOPICS; "Location" and
"Code behaviour" are the topics that need the code.
"""
import re

PLACEHOLDER = '<code_sequence>'

TOPIC_RULES = [
    ('Fix', r'\bfix|patch|mitigat|prevent|remediat|resolv|\baddress(ed|ing)?\b(?! of)|solution|recommend'
            r'|\bcorrect(ed|ion)?\b'),
    ('Severity', r'sever|cvss|score|critical|serious'),
    ('Location', r'\bwhere\b|which line|which function|locat|which part|point out|point to'
                 r'|specific (line|function|code|section|part)|what lines?\b|what function|which file'
                 r'|function that contains|vulnerable (function|code|line)'),
    ('Exploitation', r'exploit|attack|trigger|malicious'),
    ('Impact', r'impact|consequence|result|effect|risk|allow|happen if|lead to'),
    ('Vuln. type', r'what is the (type of )?vulnerab|vulnerability type|type of (the )?vulnerab'
                   r'|what (type|kind) of|\bcwe\b|categor'),
    ('Affected software', r'repositor|version|product|affected|software|project|github|vendor'
                          r'|package|library|application|plugin|component'),
    ('Code behaviour', r'purpose of|what does|what is .* doing|role of|used for'),
    ('Mechanism', r'how does|how is|how do|mechanism|cause|why|occur|\bwork|arise|reason'),
]
TOPICS = [name for name, _ in TOPIC_RULES] + ['Other']
DESCRIPTION_TOPICS = ['Vuln. type', 'Mechanism', 'Fix', 'Impact', 'Exploitation', 'Affected software']
CODE_TOPICS = ['Location', 'Code behaviour']


def topic_of(question):
    """Topic of one question (the placeholder, if present, is ignored)."""
    q = question.replace(PLACEHOLDER, '').lower()
    for name, pattern in TOPIC_RULES:
        if re.search(pattern, q):
            return name
    return 'Other'
