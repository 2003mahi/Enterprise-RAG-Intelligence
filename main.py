import os
import json
import sqlite3
import re
import requests
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import fitz  # PyMuPDF
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = FastAPI(title="Enterprise Secure RAG System", version="1.0.0")

# Database Path
DB_PATH = "data/databases/enterprise.db"

# Load security policies & user roles
with open("data/access_policies.json", "r") as f:
    POLICIES = json.load(f)

with open("data/user_roles.json", "r") as f:
    USER_ROLES = json.load(f)


# --- SIMPLE COGNITIVE VECTOR INDEX (BM25 / TF-IDF Search for Documents) ---
class SimpleDocSearchIndex:
    def __init__(self):
        self.chunks = []
        self.vocabulary = set()
        self.idf = {}
        
    def load_documents(self):
        self.chunks = []
        pdf_dir = "data/pdfs"
        if not os.path.exists(pdf_dir):
            return
            
        for file in os.listdir(pdf_dir):
            if file.endswith(".pdf"):
                file_path = os.path.join(pdf_dir, file)
                # Read metadata from access policy
                doc_policy = POLICIES["document_policies"].get(file, {
                    "classification": "Internal",
                    "department": "General"
                })
                
                doc = fitz.open(file_path)
                for page_num in range(len(doc)):
                    page = doc[page_num]
                    text = page.get_text()
                    # Segment by paragraphs
                    paragraphs = [p.strip() for p in text.split("\n\n") if len(p.strip()) > 30]
                    if not paragraphs:
                        # Fallback to whole page
                        paragraphs = [text.strip()]
                        
                    for i, para in enumerate(paragraphs):
                        self.chunks.append({
                            "source": file,
                            "title": POLICIES["document_policies"].get(file, {}).get("description", file),
                            "page": page_num + 1,
                            "classification": doc_policy["classification"],
                            "department": doc_policy["department"],
                            "text": para,
                            "id": f"{file}_p{page_num+1}_c{i}"
                        })
                doc.close()
        self._build_index()

    def _tokenize(self, text: str) -> List[str]:
        # Lowercase and extract alphanumeric words
        return re.findall(r'\b[a-z0-9_]{3,}\b', text.lower())

    def _build_index(self):
        # Build document vectors
        self.vocabulary = set()
        doc_counts = {}
        
        # Count term frequencies per chunk
        for chunk in self.chunks:
            tokens = self._tokenize(chunk["text"])
            chunk["tf"] = {}
            for t in tokens:
                chunk["tf"][t] = chunk["tf"].get(t, 0) + 1
                self.vocabulary.add(t)
            
            # Count document frequencies
            for t in set(tokens):
                doc_counts[t] = doc_counts.get(t, 0) + 1
                
        # Calculate IDF
        N = len(self.chunks)
        for term, df in doc_counts.items():
            # Standard smooth IDF formula
            import math
            self.idf[term] = math.log((N + 1) / (df + 1)) + 1

    def search(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        query_tokens = self._tokenize(query)
        if not query_tokens or not self.chunks:
            return []
            
        scores = []
        for chunk in self.chunks:
            score = 0.0
            # Calculate simple TF-IDF cosine matching
            for t in query_tokens:
                if t in chunk["tf"] and t in self.idf:
                    score += chunk["tf"][t] * self.idf[t]
            if score > 0:
                scores.append((score, chunk))
                
        # Sort descending
        scores.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in scores[:limit]]

# Initialize Search Index
search_index = SimpleDocSearchIndex()
search_index.load_documents()


# --- DATABASE SECURE ACCESS AND RUNNER ---
def run_secure_sqlite_query(sql_query: str, user_persona: str) -> Dict[str, Any]:
    """Runs a SELECT query on sqlite safely, returning sanitised rows or raising access violations."""
    user = USER_ROLES.get(user_persona)
    if not user:
        return {"status": "BLOCKED", "reason": "Unknown persona"}
        
    clearance = user["clearance"]
    department = user["department"]
    
    # 1. Parse SQL to check target tables
    # Strip whitespaces, capitalize
    clean_sql = sql_query.strip().upper()
    
    # Strictly allow SELECT queries only
    if not clean_sql.startswith("SELECT"):
        return {
            "status": "BLOCKED", 
            "reason": "Forbidden SQL Command: Only SELECT queries are permitted for safety."
        }
        
    # Check for destructive keywords
    for keyword in ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE", "REPLACE"]:
        if re.search(r'\b' + keyword + r'\b', clean_sql):
            return {
                "status": "BLOCKED",
                "reason": f"Security Alert: Destructive SQL keyword '{keyword}' detected."
            }

    # Extract table names from query
    tables = []
    for table_name in ["EMPLOYEES", "SALES_RECORDS", "INVENTORY"]:
        if table_name in clean_sql:
            tables.append(table_name.lower())
            
    if not tables:
        return {
            "status": "BLOCKED",
            "reason": "Security Alert: Unable to identify target SQL tables, or accessing unauthorized system schemas."
        }

    rbac_logs = []
    
    # Evaluate permissions for each targeted table
    clearance_order = POLICIES["clearance_hierarchy"]
    user_clearance_idx = clearance_order.index(clearance)
    
    for t in tables:
        policy = POLICIES["silo_policies"]["sql_database"]["tables"].get(t)
        if not policy:
            return {"status": "BLOCKED", "reason": f"Missing database policy for table '{t}'."}
            
        req_classification = policy["classification"]
        req_class_idx = clearance_order.index(req_classification)
        
        # Check clearance level
        if user_clearance_idx < req_class_idx:
            rbac_logs.append(f"Blocked access to SQL table '{t}' (Requires classification {req_classification}, user has {clearance})")
            return {
                "status": "BLOCKED",
                "reason": f"Access Denied: Table '{t}' requires '{req_classification}' clearance. User profile '{user_persona}' has '{clearance}' clearance.",
                "audit_logs": rbac_logs
            }
            
        # Check department constraints for highly confidential tables
        req_dept = policy["department"]
        if req_dept != "General" and department != req_dept and department != "Executive":
            # For employees table: HR only (or Finance for salary lookups, or CEO)
            # For sales records: Finance only (or CEO)
            if t == "employees" and department in ["Human Resources", "Finance"]:
                # Allowed
                pass
            else:
                rbac_logs.append(f"Blocked access to SQL table '{t}' due to departmental silo boundaries. Requires {req_dept} or Executive, user is in {department}.")
                return {
                    "status": "BLOCKED",
                    "reason": f"Access Denied: Table '{t}' belongs to the {req_dept} silo. User department is '{department}'.",
                    "audit_logs": rbac_logs
                }

    # Execute SQLite SELECT safely
    try:
        conn = sqlite3.connect(DB_PATH)
        # Use DictRow-like cursor factory
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(sql_query)
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
    except Exception as e:
        return {
            "status": "ERROR",
            "reason": f"Database execution error: {str(e)}"
        }

    # Apply Column-Level and Cell-Level Redactions
    # Salary column redaction rules:
    # Requires HR Manager/HR Assistant, Finance Lead, or CEO (Executive).
    # If other users query employees table (e.g. IT Admin who has high clearance but is in IT department), salary is redacted.
    redacted_count = 0
    sanitized_rows = []
    
    allowed_salary_departments = ["Human Resources", "Finance", "Executive"]
    
    for row in rows:
        sanitized_row = row.copy()
        if "salary" in sanitized_row:
            if department not in allowed_salary_departments:
                sanitized_row["salary"] = "[REDACTED (Requires HR/Finance Role)]"
                redacted_count += 1
        sanitized_rows.append(sanitized_row)
        
    if redacted_count > 0:
        rbac_logs.append(f"Redacted sensitive column 'salary' for {redacted_count} records due to role classification restrictions.")

    return {
        "status": "ALLOWED",
        "data": sanitized_rows,
        "audit_logs": rbac_logs
    }


# --- JSON LOGS SECURE READER ---
def run_secure_log_query(query: str, user_persona: str) -> Dict[str, Any]:
    user = USER_ROLES.get(user_persona)
    if not user:
        return {"status": "BLOCKED", "reason": "Unknown persona"}
        
    clearance = user["clearance"]
    department = user["department"]
    clearance_order = POLICIES["clearance_hierarchy"]
    user_clearance_idx = clearance_order.index(clearance)
    
    # Router maps query to JSON log file
    # Let's read both log policies
    log_silo_policies = POLICIES["silo_policies"]["json_logs"]
    
    target_files = []
    if any(k in query.lower() for k in ["security", "ssh", "attack", "brute-force", "ip", "exfiltration", "fail"]):
        target_files.append("security_alerts.json")
    if any(k in query.lower() for k in ["operation", "deploy", "backup", "cron", "cache", "server"]):
        target_files.append("operations_log.json")
        
    # Default to both if unclear
    if not target_files:
        target_files = ["security_alerts.json", "operations_log.json"]
        
    rbac_logs = []
    allowed_records = []
    
    for log_file in target_files:
        policy = log_silo_policies.get(log_file)
        if not policy:
            continue
            
        req_classification = policy["classification"]
        req_class_idx = clearance_order.index(req_classification)
        
        # Check Clearance
        if user_clearance_idx < req_class_idx:
            rbac_logs.append(f"Blocked retrieval of JSON file '{log_file}' (Requires clearance {req_classification}, user has {clearance})")
            continue
            
        # Check Department
        req_dept = policy["department"]
        if req_dept != "General" and department != req_dept and department != "Executive":
            rbac_logs.append(f"Blocked retrieval of JSON file '{log_file}' due to departmental boundaries. Requires {req_dept}, user is in {department}")
            continue
            
        # Allowed! Read log content
        file_path = os.path.join("data/logs", log_file)
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                logs_data = json.load(f)
                
            # Filter rows based on query keywords to keep context size low
            keywords = re.findall(r'\w+', query.lower())
            for entry in logs_data:
                # String representation for searching
                entry_str = json.dumps(entry).lower()
                # Calculate match strength
                match_count = sum(1 for kw in keywords if kw in entry_str)
                if match_count > 0 or len(keywords) < 3:  # If short query, include all
                    entry_copy = entry.copy()
                    entry_copy["_source_file"] = log_file
                    allowed_records.append(entry_copy)
                    
    if not allowed_records and rbac_logs:
        return {
            "status": "BLOCKED",
            "reason": "Access Denied: Attempted search on logs was blocked due to clearance levels or department constraints.",
            "audit_logs": rbac_logs
        }
        
    return {
        "status": "ALLOWED",
        "data": allowed_records[:6],  # limit context size
        "audit_logs": rbac_logs
    }


# --- THE QUERY ROUTER ---
def route_query(query: str, user_persona: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """Classifies the query intent to route to SQL, PDF Document Index, JSON logs, or multi-source."""
    query_lower = query.lower()
    
    # 1. First run a rule-based quick analysis
    has_sql_indicators = any(w in query_lower for w in ["salary", "salary band", "earn", "wage", "sales", "revenue", "price", "quantity", "inventory", "stock", "warehouse", "employee", "database", "record"])
    has_log_indicators = any(w in query_lower for w in ["log", "security alert", "firewall", "brute force", "brute-force", "ip address", "outbound", "traffic", "backup status", "deploy", "microservice", "port sweep", "port scan"])
    has_doc_indicators = any(w in query_lower for w in ["policy", "handbook", "compliance", "rule", "gift", "integrity", "artemis spec", "technical architecture", "vector db", "db credentials", "mongodb", "forecast", "allocated", "budget", "contingency", "guideline", "guidelines", "specification", "specifications", "spec", "document", "pdf", "report"])
    
    # Determine fallback route
    routes = []
    if has_sql_indicators:
        routes.append("sql")
    if has_log_indicators:
        routes.append("log")
    if has_doc_indicators:
        routes.append("pdf")
        
    # Cross-silo check (Multi-source)
    # E.g. "compare Alice's salary with the HR compensation guidelines" -> contains sql ("Alice's salary") and pdf ("guidelines")
    if len(routes) > 1:
        chosen_route = "multi"
    elif len(routes) == 1:
        chosen_route = routes[0]
    else:
        chosen_route = "pdf"  # default to doc search
        
    routing_explanation = f"Rule-based classification selected '{chosen_route}' based on text indicators."
    
    # 2. If API Key is available, verify route structure via LLM call for intelligence boost
    llm_key = api_key or os.getenv("GEMINI_API_KEY")
    if llm_key:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={llm_key}"
            headers = {"Content-Type": "application/json"}
            prompt = f"""
Analyze the following user query for an enterprise corporate portal and determine the target data silo.
Silos available:
1. "sql": SQLite database tables containing:
   - 'employees' (personnel, name, department, role, salary, clearance)
   - 'sales_records' (products sold, revenue amounts, date, region)
   - 'inventory' (it assets, quantities, prices, warehouse location)
2. "pdf": Document files search index containing:
   - 'compliance_handbook_2026.pdf' (gift policy, business compliance, data privacy audits)
   - 'hr_compensation_guidelines.pdf' (HR salary brackets, bands, performance bonuses)
   - 'project_artemis_spec.pdf' (engineering technical spec, vector DB mongodb connection strings, subnets)
   - 'annual_budget_forecast_2026.pdf' (division capital allocations, financial forecast SaaS margins)
3. "log": JSON log files containing:
   - 'security_alerts.json' (SSH brute-force alerts, suspicious port sweep logs, exfiltration reports)
   - 'operations_log.json' (system daemon backup checks, server deployments, cache purges)
4. "multi": Queries requiring cross-silo joining (e.g. comparing SQL database rows with PDF compliance standards).

User Query: "{query}"

Respond strictly with a JSON object in this format:
{{
  "route": "sql | pdf | log | multi",
  "explanation": "Brief 1-sentence reason",
  "sql_query": "If route is sql or multi, write a safe SQLite SELECT query to run (or null)",
  "extracted_keywords": ["keyword1", "keyword2"]
}}
"""
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"responseMimeType": "application/json"}
            }
            res = requests.post(url, headers=headers, json=payload, timeout=6)
            if res.status_code == 200:
                data = res.json()
                text_out = data["candidates"][0]["content"]["parts"][0]["text"]
                parsed = json.loads(text_out)
                chosen_route = parsed.get("route", chosen_route)
                routing_explanation = f"LLM Routing: {parsed.get('explanation')}"
                generated_sql = parsed.get("sql_query")
                return {
                    "route": chosen_route,
                    "explanation": routing_explanation,
                    "generated_sql": generated_sql,
                    "keywords": parsed.get("extracted_keywords", [])
                }
        except Exception as e:
            routing_explanation += f" (LLM router failed, fell back to rules: {str(e)})"
            
    # Compile a default SQL query if SQL is selected and we are in rule/fallback mode
    generated_sql = None
    if chosen_route in ["sql", "multi"]:
        # Simple extraction heuristics to construct safe SELECTs
        if "salary" in query_lower or "employee" in query_lower or "payroll" in query_lower:
            # Check if name is mentioned
            name_match = re.search(r'\b(alice|bob|charlie|dave|eva|frank|grace|henry)\b', query_lower)
            if name_match:
                name_cap = name_match.group(1).capitalize()
                generated_sql = f"SELECT name, role, department, salary, clearance_level FROM employees WHERE name LIKE '%{name_cap}%'"
            else:
                generated_sql = "SELECT name, role, department, salary, clearance_level FROM employees"
        elif "sales" in query_lower or "revenue" in query_lower or "sold" in query_lower:
            generated_sql = "SELECT id, product, amount, date, region FROM sales_records"
        elif "inventory" in query_lower or "item" in query_lower or "asset" in query_lower or "server" in query_lower or "macbook" in query_lower or "thinkpad" in query_lower:
            generated_sql = "SELECT item_name, quantity, price, warehouse FROM inventory"
            
    return {
        "route": chosen_route,
        "explanation": routing_explanation,
        "generated_sql": generated_sql,
        "keywords": re.findall(r'\w+', query_lower)
    }


# --- THE RBAC ENGINE FILTER ---
def apply_rbac_security_filters(
    route: str,
    raw_results: Dict[str, Any],
    user_persona: str,
    router_info: Dict[str, Any]
) -> Dict[str, Any]:
    """Applies strict security classification and department checks to all fetched assets."""
    user = USER_ROLES.get(user_persona)
    clearance = user["clearance"]
    department = user["department"]
    
    clearance_order = POLICIES["clearance_hierarchy"]
    user_clearance_idx = clearance_order.index(clearance)
    
    filtered_results = {
        "pdf": [],
        "sql": [],
        "log": [],
        "security_logs": []
    }
    
    # 1. Document Filter (PDF)
    if "pdf" in raw_results:
        for chunk in raw_results["pdf"]:
            req_class = chunk["classification"]
            req_class_idx = clearance_order.index(req_class)
            req_dept = chunk["department"]
            
            # Check level clearance
            if user_clearance_idx < req_class_idx:
                filtered_results["security_logs"].append(
                    f"Censored chunk from '{chunk['source']}': User has '{clearance}' but requires '{req_class}'."
                )
                continue
                
            # Check departmental boundaries (if department is locked)
            if req_dept != "General" and department != req_dept and department != "Executive":
                filtered_results["security_logs"].append(
                    f"Censored chunk from '{chunk['source']}': Siloed under department '{req_dept}' (User is in '{department}')."
                )
                continue
                
            # Allowed
            filtered_results["pdf"].append(chunk)
            
    # 2. SQL Filter
    if "sql" in raw_results:
        sql_res = raw_results["sql"]
        if sql_res.get("status") == "ALLOWED":
            filtered_results["sql"] = sql_res.get("data", [])
            if sql_res.get("audit_logs"):
                filtered_results["security_logs"].extend(sql_res["audit_logs"])
        else:
            filtered_results["security_logs"].append(
                f"SQL Execution Blocked: {sql_res.get('reason')}"
            )
            
    # 3. Logs Filter
    if "log" in raw_results:
        log_res = raw_results["log"]
        if log_res.get("status") == "ALLOWED":
            filtered_results["log"] = log_res.get("data", [])
            if log_res.get("audit_logs"):
                filtered_results["security_logs"].extend(log_res["audit_logs"])
        else:
            filtered_results["security_logs"].append(
                f"Log Retrieval Blocked: {log_res.get('reason')}"
            )
            
    return filtered_results


# --- GROUNDEDNESS / HALLUCINATION GUARD ---
def calculate_groundedness_score(answer: str, context_text: str) -> float:
    """Computes a groundedness percentage score based on overlaps of key statements."""
    if not context_text or not answer:
        return 0.0
        
    # Extract numerical figures, key noun constructs, and capitalized words
    facts = set(re.findall(r'\b\d+(?:,\d+)*(?:\.\d+)?\b|\b[A-Z][a-zA-Z0-9_]{2,}\b', answer))
    if not facts:
        return 100.0  # No specific numbers/proper nouns to verify
        
    context_text_lower = context_text.lower()
    matched_facts = 0
    
    for fact in facts:
        if fact.lower() in context_text_lower:
            matched_facts += 1
            
    return round((matched_facts / len(facts)) * 100, 1)


# --- SYNTHESIS ENGINE (DUAL MODE) ---
def generate_synthesis(
    query: str,
    context: Dict[str, Any],
    user_persona: str,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """Generates cited response using LLM or robust local deterministic template engine."""
    user = USER_ROLES.get(user_persona)
    
    # Construct context document text
    context_parts = []
    citations = []
    
    # Format PDFs
    for chunk in context["pdf"]:
        context_parts.append(
            f"Source Document: {chunk['source']} (Page {chunk['page']})\n"
            f"Classification: {chunk['classification']} | Department: {chunk['department']}\n"
            f"Content: {chunk['text']}"
        )
        citations.append({
            "source": chunk["source"],
            "type": "PDF Chunk",
            "page": chunk["page"],
            "classification": chunk["classification"],
            "detail": f"{chunk['source']} (Page {chunk['page']})"
        })
        
    # Format SQL Data
    if context["sql"]:
        sql_summary = json.dumps(context["sql"], indent=2)
        context_parts.append(f"Source Database Records:\n{sql_summary}")
        citations.append({
            "source": "SQLite Database",
            "type": "Database Row",
            "classification": "Confidential / Internal",
            "detail": f"Database tables queried safely. Redacted cells applied if any."
        })
        
    # Format Logs
    for log_line in context["log"]:
        source_file = log_line.get("_source_file", "JSON Log")
        log_id = log_line.get("log_id", log_line.get("log_id", "LOG"))
        context_parts.append(
            f"Source Log: {source_file} (Log ID: {log_id})\n"
            f"Content: {json.dumps(log_line)}"
        )
        citations.append({
            "source": source_file,
            "type": "Log Line",
            "classification": "Restricted / Internal",
            "detail": f"{source_file} - Log ID {log_id}"
        })
        
    context_text = "\n\n---\n\n".join(context_parts)
    
    llm_key = api_key or os.getenv("GEMINI_API_KEY")
    
    # 1. Live LLM Generation Mode
    if llm_key and context_parts:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={llm_key}"
            headers = {"Content-Type": "application/json"}
            
            system_prompt = f"""
You are a highly secure, enterprise-grade AI assistant. Your role is to answer user queries using ONLY the provided contexts.
Do not hallucinate. Do not use external facts.
Strictly enforce citations in the format `[Source: filename.pdf (Page X)]` or `[Source: SQL database]` or `[Source: logfile.json (ID: X)]` when stating facts.
If a retrieved cell says `[REDACTED]`, explain that the user does not have sufficient role clearance to view that specific field.

User Profile:
- Name: {user['name']}
- Role: {user['role']}
- Department: {user['department']}
- Security Clearance: {user['clearance']}
"""
            prompt = f"""
Contexts available:
{context_text}

User Query: "{query}"

Generate a helpful, grounded, and concise response with clear source citations.
"""
            payload = {
                "contents": [
                    {"role": "user", "parts": [{"text": system_prompt + "\n\n" + prompt}]}
                ]
            }
            res = requests.post(url, headers=headers, json=payload, timeout=10)
            if res.status_code == 200:
                answer = res.json()["candidates"][0]["content"]["parts"][0]["text"]
                groundedness_score = calculate_groundedness_score(answer, context_text)
                return {
                    "answer": answer,
                    "citations": citations,
                    "groundedness_score": groundedness_score,
                    "llm_powered": True
                }
        except Exception as e:
            # Continue to fallback on LLM failure
            pass

    # 2. Local Deterministic Synthesis Fallback Compiler
    # Write custom reasoning compiler to formulate high-quality responses based on text query matches
    query_lower = query.lower()
    answer_lines = []
    
    if not context_parts:
        # No context retrieved (or blocked)
        if context["security_logs"]:
            denied_list = [log for log in context["security_logs"] if "Blocked" in log or "Censored" in log or "Access Denied" in log]
            if denied_list:
                answer = "Access Denied. Your query was blocked by the security enforcer engine. Details:\n- " + "\n- ".join(denied_list)
            else:
                answer = "Your query was processed but no accessible information was found within your current clearance level."
        else:
            answer = "No records matching your search query were found in the database or document repositories."
        return {
            "answer": answer,
            "citations": [],
            "groundedness_score": 100.0,
            "llm_powered": False
        }

    # Custom compiler structures depending on the silo
    answer_lines.append(f"### Secure Synthesis (Fallback Engine)")
    
    # PDF context compilation
    pdf_chunks = context["pdf"]
    if pdf_chunks:
        answer_lines.append("\n**Information retrieved from Corporate Documents:**")
        for c in pdf_chunks:
            source_file = c["source"]
            page = c["page"]
            text_preview = c["text"]
            # Extract key statements
            statements = text_preview.split(". ")
            for stmt in statements:
                if any(kw in stmt.lower() for kw in query_lower.split()):
                    answer_lines.append(f"- {stmt.strip()} [Source: {source_file} (Page {page})]")
            # Fallback if no specific keyword match
            if len(answer_lines) == 1 or (len(answer_lines) == 2 and pdf_chunks):
                answer_lines.append(f"- {statements[0].strip()}... [Source: {source_file} (Page {page})]")

    # SQL context compilation
    sql_rows = context["sql"]
    if sql_rows:
        answer_lines.append("\n**Retrieved Database Records:**")
        for row in sql_rows:
            # Build string summary
            row_items = []
            name = row.get("name", row.get("item_name", "Record"))
            role = row.get("role")
            dept = row.get("department")
            salary = row.get("salary")
            
            # Employee specific compile
            if role and dept:
                salary_str = f"Salary: {salary}" if salary else "Salary: [REDACTED]"
                row_items.append(f"Employee {name} ({role} in {dept}). {salary_str}.")
            else:
                # General row values
                row_vals = ", ".join([f"{k}: {v}" for k, v in row.items() if k != "id"])
                row_items.append(f"{name} -> {row_vals}")
                
            for item in row_items:
                answer_lines.append(f"- {item} [Source: SQL Database]")

    # Log context compilation
    log_rows = context["log"]
    if log_rows:
        answer_lines.append("\n**Retrieved Operations and Security Logs:**")
        for row in log_rows:
            source_file = row["_source_file"]
            event = row.get("event_type", "System Activity")
            details = row.get("details", row.get("message", "Activity logged."))
            time = row.get("timestamp", "N/A")
            log_id = row.get("log_id", "LOG")
            answer_lines.append(f"- [{time}] Alert {event} (ID: {log_id}): '{details}' [Source: {source_file}]")

    # Add security redacted disclaimer if log blockings occurred
    if context["security_logs"]:
        blocked_events = [log for log in context["security_logs"] if "Blocked" in log or "Censored" in log]
        if blocked_events:
            answer_lines.append("\n*Note: Some context assets were redacted or excluded based on your current role authorization guidelines.*")

    answer = "\n".join(answer_lines)
    groundedness_score = calculate_groundedness_score(answer, context_text)
    
    return {
        "answer": answer,
        "citations": citations,
        "groundedness_score": groundedness_score,
        "llm_powered": False
    }


# --- REST API CLASS STRUCTURES ---
class QueryRequest(BaseModel):
    query: str
    persona: str
    api_key: Optional[str] = None

@app.post("/api/query")
async def execute_rag_pipeline(req: QueryRequest):
    query = req.query
    persona = req.persona
    api_key = req.api_key
    
    # 1. Fetch User details
    user = USER_ROLES.get(persona)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid persona selected.")
        
    # 2. Route Query
    router_info = route_query(query, persona, api_key)
    route = router_info["route"]
    
    # Gather raw query results
    raw_results = {}
    
    # Query databases if SQL route or multi-route is selected
    if route in ["sql", "multi"]:
        sql_query = router_info["generated_sql"]
        if sql_query:
            raw_results["sql"] = run_secure_sqlite_query(sql_query, persona)
        else:
            raw_results["sql"] = {
                "status": "BLOCKED",
                "reason": "System was unable to automatically compile a secure SQL statement for this database query."
            }
            
    # Query documents if PDF route or multi-route is selected
    if route in ["pdf", "multi"]:
        raw_results["pdf"] = search_index.search(query, limit=3)
        
    # Query logs if log route or multi-route is selected
    if route in ["log", "multi"]:
        raw_results["log"] = run_secure_log_query(query, persona)
        
    # 3. Apply RBAC Policies (Security Filtration)
    sanitized_context = apply_rbac_security_filters(route, raw_results, persona, router_info)
    
    # 4. Generate Synthesis with citations
    synthesis_results = generate_synthesis(query, sanitized_context, persona, api_key)
    
    # 5. Return complete payload
    return {
        "query": query,
        "persona": persona,
        "persona_details": user,
        "routing": {
            "route": route,
            "explanation": router_info["explanation"],
            "generated_sql": router_info["generated_sql"]
        },
        "rbac_audit_trail": sanitized_context["security_logs"],
        "answer": synthesis_results["answer"],
        "citations": synthesis_results["citations"],
        "groundedness_score": synthesis_results["groundedness_score"],
        "llm_powered": synthesis_results["llm_powered"],
        "retrieved_count": len(sanitized_context["pdf"]) + len(sanitized_context["sql"]) + len(sanitized_context["log"])
    }

@app.get("/api/data")
async def get_data_catalog(request: Request):
    """Provides structural visualization of files, tables, logs, and metadata schema details."""
    catalog = {
        "pdfs": [],
        "database": {
            "tables": {}
        },
        "logs": {}
    }
    
    # PDFs
    pdf_dir = "data/pdfs"
    if os.path.exists(pdf_dir):
        for file in os.listdir(pdf_dir):
            if file.endswith(".pdf"):
                file_path = os.path.join(pdf_dir, file)
                policy = POLICIES["document_policies"].get(file, {})
                catalog["pdfs"].append({
                    "name": file,
                    "size_bytes": os.path.getsize(file_path),
                    "classification": policy.get("classification"),
                    "department": policy.get("department"),
                    "description": policy.get("description")
                })
                
    # SQLite Database Table structures
    if os.path.exists(DB_PATH):
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            # Fetch table schemas
            for table_name in ["employees", "sales_records", "inventory"]:
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = [{"name": c[1], "type": c[2]} for c in cursor.fetchall()]
                policy = POLICIES["silo_policies"]["sql_database"]["tables"].get(table_name, {})
                catalog["database"]["tables"][table_name] = {
                    "columns": columns,
                    "classification": policy.get("classification"),
                    "department": policy.get("department"),
                    "description": policy.get("description")
                }
            conn.close()
        except Exception as e:
            catalog["database"]["error"] = str(e)
            
    # Logs
    log_dir = "data/logs"
    if os.path.exists(log_dir):
        for file in os.listdir(log_dir):
            if file.endswith(".json"):
                file_path = os.path.join(log_dir, file)
                policy = POLICIES["silo_policies"]["json_logs"].get(file, {})
                catalog["logs"][file] = {
                    "size_bytes": os.path.getsize(file_path),
                    "classification": policy.get("classification"),
                    "department": policy.get("department"),
                    "description": policy.get("description")
                }
                
    return catalog

@app.get("/api/policies")
async def get_governance_policies():
    """Returns access policies and user mapping."""
    return {
        "policies": POLICIES,
        "users": USER_ROLES
    }

# Serve Static files (web UI HTML/CSS/JS)
os.makedirs("static", exist_ok=True)
app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    # Start on port 8000
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
