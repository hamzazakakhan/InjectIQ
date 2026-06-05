"""
InjectIQ v2 — AI-Native Database Exploitation Framework
Built from scratch. Not a sqlmap wrapper.

ARCHITECTURE (modeled on sqlmap's proven patterns, rebuilt for 2026):
  sqlmap flow:  checks.py → agent.py → inject.py → techniques/ → comparison.py
  InjectIQ flow: probe.py → payload.py → inject.py → techniques/ → comparator.py

Key differences from sqlmap:
  - sqlmap: 30 SQL DBMS plugins, 0 NoSQL, 0 GraphQL
  - InjectIQ: SQL + NoSQL (MongoDB/Redis/Cassandra/DynamoDB) + GraphQL (Apollo/Hasura)
  - sqlmap: 68 tamper scripts (all regex-based, last updated 2019)
  - InjectIQ: AI-generated tamper per WAF + parser differential engine + HTTP/2 smuggling
  - sqlmap: No WAF origin bypass (BreakingWAF technique)
  - InjectIQ: CDN origin IP discovery -> direct-to-origin injection bypass
  - sqlmap: No parameterized query bypass
  - InjectIQ: Second-order + OOB + ORDER BY blind + stored injection chains
  - sqlmap: comparison.py uses difflib SequenceMatcher (page similarity)
  - InjectIQ: AI response analysis + structural DOM diff + statistical timing analysis
"""

__version__ = "2.0.0"
