import json
from main import route_query, run_secure_sqlite_query, run_secure_log_query, apply_rbac_security_filters, generate_synthesis, search_index

def run_test(query: str, persona: str):
    print(f"\n==========================================")
    print(f"QUERY: '{query}'")
    print(f"PERSONA: {persona}")
    print(f"==========================================")
    
    # 1. Router
    router_info = route_query(query, persona)
    print(f"-> Selected Route: {router_info['route']}")
    print(f"-> Routing Reason: {router_info['explanation']}")
    if router_info.get("generated_sql"):
        print(f"-> Generated SQL: {router_info['generated_sql']}")
        
    # Gather raw
    raw = {}
    if router_info["route"] in ["sql", "multi"]:
        raw["sql"] = run_secure_sqlite_query(router_info["generated_sql"], persona)
        if raw["sql"].get("status") == "BLOCKED":
            print(f"-> SQL Blocked: {raw['sql']['reason']}")
        else:
            print(f"-> SQL Allowed (fetched {len(raw['sql'].get('data', []))} rows)")
            if raw["sql"].get("data"):
                print(f"   First row sample: {raw['sql']['data'][0]}")
                
    if router_info["route"] in ["pdf", "multi"]:
        raw["pdf"] = search_index.search(query, limit=3)
        print(f"-> Document search fetched {len(raw['pdf'])} chunks")
        
    if router_info["route"] in ["log", "multi"]:
        raw["log"] = run_secure_log_query(query, persona)
        if raw["log"].get("status") == "BLOCKED":
            print(f"-> Log Blocked: {raw['log']['reason']}")
        else:
            print(f"-> Log Allowed (fetched {len(raw['log'].get('data', []))} rows)")
            
    # 2. RBAC Filter
    filtered = apply_rbac_security_filters(router_info["route"], raw, persona, router_info)
    print(f"-> Security Audit Logs:")
    for log in filtered["security_logs"]:
        print(f"   [AUDIT] {log}")
        
    # 3. Generate Answer
    synthesis = generate_synthesis(query, filtered, persona)
    print(f"\n-> SYNTHESIZED RESPONSE:\n{synthesis['answer']}")
    print(f"-> Groundedness Index: {synthesis['groundedness_score']}%")
    print(f"------------------------------------------\n")

if __name__ == "__main__":
    # Test 1: Public Guest tries to fetch salary
    run_test("What is Alice Smith's salary?", "guest_public")
    
    # Test 2: HR Manager fetches salary
    run_test("What is Alice Smith's salary?", "alice_hr")
    
    # Test 3: IT Admin tries to fetch salary (Clearance is Restricted, but department is IT, not HR!)
    run_test("What is Alice Smith's salary?", "charlie_it")
    
    # Test 4: IT Admin searches for Project Artemis Spec (Restricted document)
    run_test("What is the technical server architecture for Project Artemis?", "charlie_it")
    
    # Test 5: HR Manager searches for Project Artemis Spec (Engineering Restricted document)
    run_test("What is the technical server architecture for Project Artemis?", "alice_hr")
    
    # Test 6: Multi-source search run by HR Manager
    run_test("Compare Alice's salary with the HR compensation guidelines.", "alice_hr")
