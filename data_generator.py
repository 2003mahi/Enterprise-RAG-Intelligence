import os
import json
import sqlite3
import fitz  # PyMuPDF, installed in the system environment

# Ensure directories exist
os.makedirs("data/pdfs", exist_ok=True)
os.makedirs("data/databases", exist_ok=True)
os.makedirs("data/logs", exist_ok=True)

# 1. Access Policies Config
access_policies = {
    "clearance_hierarchy": ["Public", "Internal", "Confidential", "Restricted"],
    "document_policies": {
        "compliance_handbook_2026.pdf": {
            "classification": "Internal",
            "department": "General",
            "description": "Standard corporate operating procedures and compliance mandates."
        },
        "hr_compensation_guidelines.pdf": {
            "classification": "Confidential",
            "department": "Human Resources",
            "description": "Corporate salary bands, structures, and compensation guidelines."
        },
        "project_artemis_spec.pdf": {
            "classification": "Restricted",
            "department": "Engineering",
            "description": "Technical architecture blueprint and secret configuration parameters for Project Artemis."
        },
        "annual_budget_forecast_2026.pdf": {
            "classification": "Confidential",
            "department": "Finance",
            "description": "Financial forecasts, revenue targets, and detailed capital allocations."
        }
    },
    "silo_policies": {
        "sql_database": {
            "tables": {
                "employees": {
                    "classification": "Confidential",
                    "department": "Human Resources",
                    "description": "Employee personnel database. Salary column requires explicit Confidential clearance + HR/Finance department access."
                },
                "sales_records": {
                    "classification": "Confidential",
                    "department": "Finance",
                    "description": "Corporate transaction and revenue database."
                },
                "inventory": {
                    "classification": "Internal",
                    "department": "Operations",
                    "description": "Warehouse stock levels and equipment pricing."
                }
            }
        },
        "json_logs": {
            "security_alerts.json": {
                "classification": "Restricted",
                "department": "Information Technology",
                "description": "Security events, log audits, firewall records, and server login failures."
            },
            "operations_log.json": {
                "classification": "Internal",
                "department": "Operations",
                "description": "System deploy logs, automated database backup statuses, and batch jobs."
            }
        }
    }
}

with open("data/access_policies.json", "w") as f:
    json.dump(access_policies, f, indent=4)
print("Generated data/access_policies.json")

# 2. User Persona Mappings
user_roles = {
    "eva_ceo": {
        "name": "Eva Vance",
        "role": "CEO",
        "department": "Executive",
        "clearance": "Restricted",
        "description": "Executive oversight. Full access to all security clearances and departmental data silos."
    },
    "alice_hr": {
        "name": "Alice Smith",
        "role": "HR Manager",
        "department": "Human Resources",
        "clearance": "Confidential",
        "description": "Manages personnel details, payroll policies, and employee compensation guidelines."
    },
    "bob_finance": {
        "name": "Bob Miller",
        "role": "Finance Lead",
        "department": "Finance",
        "clearance": "Confidential",
        "description": "Oversees corporate budgets, audits sales transactions, and performs budget projections."
    },
    "charlie_it": {
        "name": "Charlie Davis",
        "role": "IT Administrator",
        "department": "Information Technology",
        "clearance": "Restricted",
        "description": "Monitors network architecture, examines security firewall logs, and manages IT infrastructure."
    },
    "dave_support": {
        "name": "Dave Wilson",
        "role": "Customer Support Specialist",
        "department": "Customer Support",
        "clearance": "Internal",
        "description": "Assists customers and checks inventory details. No access to Confidential or Restricted files."
    },
    "guest_public": {
        "name": "Anonymous Visitor",
        "role": "Guest",
        "department": "None",
        "clearance": "Public",
        "description": "External reviewer. Access restricted purely to Public corporate documentation."
    }
}

with open("data/user_roles.json", "w") as f:
    json.dump(user_roles, f, indent=4)
print("Generated data/user_roles.json")

# 3. PDF Generator Helper (using PyMuPDF)
def create_pdf(filename, title, content_paragraphs):
    doc = fitz.open()
    page = doc.new_page()
    
    # Simple layout math
    y = 50
    # Insert Title
    page.insert_text((50, y), title, fontsize=20, color=(0.1, 0.3, 0.6))
    y += 40
    
    # Insert content
    for para in content_paragraphs:
        # Wrap paragraphs (fitz insert_textbox is better for wrapping text)
        rect = fitz.Rect(50, y, 550, y + 150)
        page.insert_textbox(rect, para, fontsize=11, fontname="helv", color=(0.15, 0.15, 0.15))
        y += 120
        if y > 700:
            page = doc.new_page()
            y = 50
            
    doc.save(f"data/pdfs/{filename}")
    doc.close()
    print(f"Generated data/pdfs/{filename}")

# Generate PDFs
create_pdf(
    "compliance_handbook_2026.pdf",
    "Corporate Compliance Handbook 2026",
    [
        "1. GENERAL BUSINESS INTEGRITY POLICY\nAll employees must perform their roles with complete integrity. Compliance is mandatory for all divisions. Gifts or hospitality items exceeding $100 in value cannot be accepted from external vendors. Anything above this threshold must be logged with the compliance department immediately.",
        "2. DATA PRIVACY AND SECURITY MEASURES\nProtecting corporate data is critical. Compliance requires that all customer PII (Personally Identifiable Information) must be encrypted at rest and in transit. Standard internal emails must not disclose corporate source code or server configurations.",
        "3. AUDITS AND INVESTIGATIONS\nAnnual compliance reviews are scheduled every October. Internal auditors will randomly inspect operational logs and expense claims to verify compliance. Non-compliance results in disciplinary action up to termination of contract."
    ]
)

create_pdf(
    "hr_compensation_guidelines.pdf",
    "HR Compensation and Salary Guidelines 2026",
    [
        "1. PAY GRADE AND BASE SALARY STRUCTURE\nOur compensation bands align employee compensation with industry standards. Band A (Entry): $40,000 - $65,000. Band B (Professional): $65,000 - $110,000. Band C (Senior Manager): $110,000 - $180,000. Band D (Executive): $180,000 - $350,000.",
        "2. PERFORMANCE REVIEW AND BONUS INCENTIVES\nBonuses are calculated annually based on individual and corporate performance metrics. Standard performance modifiers scale bonuses between 0% and 20% of base salary. Reviews take place in June and December.",
        "3. EXCLUSIVE PERSONNEL BENEFIT OFFERS\nConfidential benefit plans include health plans, gym memberships, and stock options. Executive compensation plans (Band D) are subject to specialized board approval and are treated as confidential information with highly restricted access."
    ]
)

create_pdf(
    "project_artemis_spec.pdf",
    "Project Artemis Technical Specifications",
    [
        "1. SYSTEM ARCHITECTURE AND SERVER HOSTS\nProject Artemis is our next-generation RAG search index core. The production servers reside inside a secure Virtual Private Cloud (VPC) at IP subnets 10.240.12.0/24. Production API load balancers operate under private domain 'artemis-prod-internal.corp'.",
        "2. SECRET DATABASE AND VECTOR ACCESS CREDENTIALS\nRestricted Access Alert: Credentials to the primary vector database instance are stored in the secret manager at path 'env/prod/vectordb'. The master connection string is 'mongodb+srv://artemis_admin:K8s_pass_9981@cluster0.corp.internal/artemis'. Backup snapshots are stored in bucket 's3://artemis-secrets-backup-2026'.",
        "3. CORE RETRIEVAL ALGORITHMS\nArtemis uses a dense vector retriever coupled with a cross-encoder reranker. The embedding model is 'text-embedding-3-large' mapped to a 1024-dimensional space. Semantic threshold filters are set to 0.76 to guarantee high relevance and suppress generic retrieval."
    ]
)

create_pdf(
    "annual_budget_forecast_2026.pdf",
    "Annual Corporate Budget and Revenue Forecast 2026",
    [
        "1. TOTAL CAPITAL ALLOCATIONS BY DIVISION\nFor FY 2026, the corporate operating budget is set to $12,500,000. Engineering is allocated $4,500,000. Marketing receives $3,000,000. Human Resources is allocated $1,500,000. Customer Support receives $1,000,000. Administrative reserves are $2,500,000.",
        "2. PROJECTED REVENUE TARGETS AND CASHFLOWS\nFinance projects a gross revenue target of $18,000,000, driven by SaaS subscriptions (70%) and corporate service contracts (30%). Operating margin targets are locked at 32%. Breakeven is forecasted for late Q3 2026.",
        "3. CONFIDENTIAL DEBT & RISK REASSESSMENT\nRisks include supply-chain fluctuations and potential legal overheads. Contingency funds of $500,000 are parked under Restricted Administrative Account 'Escrow-9182' for unforeseen compliance expenses."
    ]
)

# 4. SQLite Database Generator
db_path = "data/databases/enterprise.db"
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Create tables
cursor.execute("""
CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY,
    name TEXT,
    role TEXT,
    department TEXT,
    salary REAL,
    clearance_level TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS sales_records (
    id INTEGER PRIMARY KEY,
    product TEXT,
    amount REAL,
    date TEXT,
    region TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS inventory (
    id INTEGER PRIMARY KEY,
    item_name TEXT,
    quantity INTEGER,
    price REAL,
    warehouse TEXT
)
""")

# Insert Employees
employees_data = [
    (1, "Eva Vance", "CEO", "Executive", 280000.0, "Restricted"),
    (2, "Alice Smith", "HR Manager", "Human Resources", 95000.0, "Confidential"),
    (3, "Bob Miller", "Finance Lead", "Finance", 115000.0, "Confidential"),
    (4, "Charlie Davis", "IT Administrator", "Information Technology", 88000.0, "Restricted"),
    (5, "Dave Wilson", "Support Specialist", "Customer Support", 52000.0, "Internal"),
    (6, "Frank Thomas", "Senior Engineer", "Engineering", 145000.0, "Restricted"),
    (7, "Grace Hopper", "HR Assistant", "Human Resources", 60000.0, "Confidential"),
    (8, "Henry Ford", "Sales Exec", "Sales", 75000.0, "Internal")
]

cursor.executemany("INSERT OR REPLACE INTO employees VALUES (?, ?, ?, ?, ?, ?)", employees_data)

# Insert Sales Records
sales_data = [
    (101, "SaaS License Enterprise", 50000.00, "2026-01-15", "North America"),
    (102, "Implementation Services", 15000.00, "2026-02-01", "Europe"),
    (103, "SaaS License SMB", 8500.00, "2026-02-12", "Asia-Pacific"),
    (104, "Technical Training Package", 3500.00, "2026-03-05", "North America"),
    (105, "SaaS License Enterprise", 50000.00, "2026-03-20", "Europe")
]

cursor.executemany("INSERT OR REPLACE INTO sales_records VALUES (?, ?, ?, ?, ?)", sales_data)

# Insert Inventory
inventory_data = [
    (1, "Dell PowerEdge Server R760", 4, 8500.00, "HQ Server Room"),
    (2, "Cisco Webex Board Pro 75", 3, 9200.00, "HQ Conference Space"),
    (3, "MacBook Pro M3 Max 16-inch", 15, 3499.00, "IT Asset Storage"),
    (4, "Lenovo ThinkPad X1 Carbon", 25, 1599.00, "IT Asset Storage"),
    (5, "Aruba CX 6300M Switch", 5, 4100.00, "HQ IT Rack 04")
]

cursor.executemany("INSERT OR REPLACE INTO inventory VALUES (?, ?, ?, ?, ?)", inventory_data)

conn.commit()
conn.close()
print(f"Generated SQLite Database: {db_path}")

# 5. JSON Logs Generator
security_alerts = [
    {
        "log_id": "SEC-001",
        "timestamp": "2026-05-24T01:12:45Z",
        "severity": "CRITICAL",
        "ip_address": "198.51.100.42",
        "event_type": "Unauthorized Access Attempt",
        "details": "Brute-force SSH attack detected on server host 'artemis-prod-db-01' (IP: 10.240.12.15). Lockout triggered after 12 consecutive failed login attempts using username 'root'."
    },
    {
        "log_id": "SEC-002",
        "timestamp": "2026-05-24T03:45:10Z",
        "severity": "MEDIUM",
        "ip_address": "172.16.89.5",
        "event_type": "Port Scan Detected",
        "details": "Internal port sweep targeting DB subnet 10.240.12.0/24 from workstation assigned to user ID 'charlie_it' (IP: 10.240.12.9). Operations logs checked; action was associated with scheduled vulnerability scanner job."
    },
    {
        "log_id": "SEC-003",
        "timestamp": "2026-05-24T07:30:22Z",
        "severity": "HIGH",
        "ip_address": "203.0.113.111",
        "event_type": "Data Exfiltration Flag",
        "details": "Abnormal volume of outbound traffic detected from S3 backup snapshots bucket 's3://artemis-secrets-backup-2026'. Outbound volume totaled 4.2GB in 15 minutes. Data source IP flagged as untrusted geographical zone. API key used: Admin token 9182."
    }
]

with open("data/logs/security_alerts.json", "w") as f:
    json.dump(security_alerts, f, indent=4)
print("Generated data/logs/security_alerts.json")

operations_log = [
    {
        "log_id": "OPS-101",
        "timestamp": "2026-05-23T23:00:00Z",
        "event_type": "Automated Backup",
        "status": "SUCCESS",
        "user_id": "system_daemon",
        "message": "Routine database snapshot for enterprise.db successfully uploaded to AWS S3 bucket 'corp-database-backups' (Size: 1.4 MB)."
    },
    {
        "log_id": "OPS-102",
        "timestamp": "2026-05-24T04:15:00Z",
        "event_type": "Server Deployment",
        "status": "SUCCESS",
        "user_id": "charlie_it",
        "message": "Deployment of microservice 'artemis-retriever-api' (v1.2.4) completed to Kubernetes cluster node 'worker-node-03'."
    },
    {
        "log_id": "OPS-103",
        "timestamp": "2026-05-24T08:00:00Z",
        "event_type": "Cache Flushed",
        "status": "SUCCESS",
        "user_id": "system_cron",
        "message": "Semantic cache for user vector searches expired and flushed. 412 obsolete cache keys purged."
    }
]

with open("data/logs/operations_log.json", "w") as f:
    json.dump(operations_log, f, indent=4)
print("Generated data/logs/operations_log.json")

print("\n--- SYNTHETIC DATASET GENERATION COMPLETE ---")
