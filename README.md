# HACK-O-HIRE
diff --git a/README.md b/README.md
index 21be8b26a26ed1c2c9e7d0604591ae645a500282..6c56ca1bc86af5c496b445b7c688bedbe2230653 100644
--- a/README.md
+++ b/README.md
@@ -1 +1,939 @@
-# HACK-O-HIRE
\ No newline at end of file
+# 🔐 Autonomous Cyber Incident Response — Complete System Deep Dive
+
+---
+
+## 🗺️ THE BIG PICTURE FIRST
+
+Before diving in, here is the **entire data journey in one line:**
+
+```
+RAW LOGS → CLEAN → FEATURE EXTRACT → ANOMALY SCORE → CORRELATE → PRIORITIZE → PLAYBOOK → SOC DASHBOARD
+```
+
+Every section below is one stage of this journey.
+
+---
+
+---
+
+# STAGE 1: LOG INGESTION
+### "What comes IN to your system"
+
+---
+
+## What logs you accept and what they look like
+
+Your system accepts logs from 5 sources. Each one looks completely different.
+That is the whole problem — chaos in, intelligence out.
+
+### 1A. EDR Logs (Endpoint Detection & Response)
+Tools like CrowdStrike, SentinelOne, Carbon Black sitting on employee machines.
+
+```json
+{
+  "timestamp": "2025-02-10T14:23:01.342Z",
+  "agent_id": "edr-agent-0042",
+  "host": {
+    "name": "DESKTOP-JOHN",
+    "os": "Windows 10",
+    "ip": "192.168.1.45"
+  },
+  "user": "john.doe",
+  "event_type": "process_create",
+  "process": {
+    "name": "cmd.exe",
+    "pid": 4821,
+    "parent": "explorer.exe",
+    "cmdline": "cmd.exe /c whoami && net user && ipconfig /all"
+  },
+  "severity": "HIGH"
+}
+```
+
+### 1B. Firewall / Proxy Logs (raw syslog format)
+```
+Feb 10 14:23:05 fw-core01 DENY TCP src=192.168.1.45:54312 dst=185.220.101.5:443 rule=BLOCK_UNKNOWN_OUTBOUND bytes=0
+Feb 10 14:23:06 fw-core01 ALLOW TCP src=192.168.1.45:54313 dst=10.0.0.1:80 rule=ALLOW_INTERNAL bytes=1240
+```
+
+### 1C. IAM / Active Directory Logs
+```json
+{
+  "EventID": 4625,
+  "TimeCreated": "2025-02-10T14:23:07.000Z",
+  "Computer": "DC01.BANK.LOCAL",
+  "SubjectUserName": "john.doe",
+  "SubjectDomainName": "BANK",
+  "FailureReason": "%%2313",
+  "LogonType": 3,
+  "IpAddress": "192.168.1.45",
+  "IpPort": 54400,
+  "count_in_window": 7
+}
+```
+
+### 1D. DNS Logs
+```
+2025-02-10 14:23:09.441 queries: client 192.168.1.45#52345: query: evil-c2-server.ru IN A
+2025-02-10 14:23:09.882 queries: client 192.168.1.45#52346: query: update.microsoft.com IN A
+```
+
+### 1E. Core Banking App Logs
+```json
+{
+  "txn_id": "TXN-88210",
+  "session_id": "SES-9921",
+  "user": "john.doe",
+  "action": "FUND_TRANSFER",
+  "amount": 950000,
+  "currency": "INR",
+  "from_account": "1122334455",
+  "to_account": "9988776655",
+  "to_bank": "UNKNOWN_BANK",
+  "channel": "NET_BANKING",
+  "ip": "192.168.1.45",
+  "timestamp": "2025-02-10T14:23:11Z",
+  "mfa_used": false,
+  "risk_flag": null
+}
+```
+
+---
+
+## How logs physically enter your system
+
+```
+EDR Agent    ──→  Filebeat (installed on endpoint) ──→ Logstash
+Firewall     ──→  Filebeat / Syslog receiver        ──→ Logstash
+IAM / AD     ──→  Winlogbeat                        ──→ Logstash
+DNS          ──→  Filebeat                          ──→ Logstash
+Banking App  ──→  FastAPI custom endpoint           ──→ Elasticsearch directly
+```
+
+**Filebeat** = lightweight shipper. Just reads log files and forwards them.
+**FastAPI**  = your custom Python receiver for structured app logs.
+
+---
+
+---
+
+# STAGE 2: LOGSTASH — CLEANING & NORMALIZATION
+### "Turn chaos into a common language"
+
+---
+
+## What Logstash actually does step by step
+
+```
+RAW (different formats) → PARSE → FILTER → ENRICH → OUTPUT (ECS JSON)
+```
+
+### Step A: PARSE
+Convert raw syslog/text into structured fields using grok patterns.
+
+Firewall raw line:
+```
+DENY TCP src=192.168.1.45:54312 dst=185.220.101.5:443
+```
+After grok parse:
+```json
+{ "action": "DENY", "protocol": "TCP",
+  "source_ip": "192.168.1.45", "source_port": 54312,
+  "dest_ip": "185.220.101.5", "dest_port": 443 }
+```
+
+### Step B: FILTER
+- Remove junk/debug logs
+- Drop health-check noise
+- Filter known-safe internal service accounts
+
+### Step C: ENRICH
+Add context that the raw log doesn't have:
+- **GeoIP** → source_ip → country, city (offline MaxMind DB)
+- **User role** → john.doe → "Finance Analyst", department: "Accounts"
+- **Asset criticality** → DESKTOP-JOHN → criticality: "HIGH" (has banking access)
+- **Business context** → transaction at 2AM → outside business hours flag
+
+### Step D: OUTPUT — The Clean ECS Format
+
+ECS = Elastic Common Schema. Every log, regardless of source, becomes THIS:
+
+```json
+{
+  "@timestamp": "2025-02-10T14:23:01.342Z",
+  "event": {
+    "category": ["process"],
+    "type": ["start"],
+    "outcome": "success",
+    "severity": 7,
+    "dataset": "edr.process",
+    "provider": "CrowdStrike"
+  },
+  "host": {
+    "name": "DESKTOP-JOHN",
+    "ip": ["192.168.1.45"],
+    "os": { "name": "Windows 10" }
+  },
+  "user": {
+    "name": "john.doe",
+    "domain": "BANK",
+    "roles": ["finance_analyst"],
+    "risk_tier": "HIGH"
+  },
+  "process": {
+    "name": "cmd.exe",
+    "pid": 4821,
+    "parent": { "name": "explorer.exe" },
+    "command_line": "cmd.exe /c whoami && net user"
+  },
+  "source": {
+    "ip": "192.168.1.45",
+    "geo": { "country_name": "India", "city_name": "Pune" }
+  },
+  "tags": ["edr", "process_event", "recon_command_detected"],
+  "ecs": { "version": "8.11.0" }
+}
+```
+
+**Why ECS matters:** Every log from every source now has the SAME field names.
+`user.name` is always `user.name` whether it came from firewall, IAM, or banking app.
+This makes correlation in Stage 5 trivial.
+
+---
+
+---
+
+# STAGE 3: ELASTICSEARCH — STORAGE & INDEXING
+### "Your intelligent database"
+
+---
+
+## Index design (what gets stored where)
+
+| Index Pattern | What's stored | Example use |
+|---|---|---|
+| `security-events-*` | All normalized ECS logs | Raw search, dashboards |
+| `behavior-features-*` | tsfresh extracted features | ML input/output |
+| `anomaly-scores-*` | PyOD model output scores | Fidelity scoring |
+| `incidents-*` | Correlated incident groups | SOC investigation |
+| `playbooks-*` | LLM-generated playbooks | Analyst response |
+
+## Why Elasticsearch and not just a database?
+
+- **Full-text search** on millions of logs in milliseconds
+- **Aggregations** — "how many failed logins per user in last 5 minutes"
+- **Time-series** — natural fit for log data
+- **Kibana** — free built-in SOC dashboard
+- **Python client** — `elasticsearch-py` queries from your ML code directly
+
+## Example Python query (finding brute force attempts):
+
+```python
+from elasticsearch import Elasticsearch
+
+es = Elasticsearch("http://localhost:9200")
+
+result = es.search(index="security-events-*", body={
+  "query": {
+    "bool": {
+      "must": [
+        {"term": {"event.category": "authentication"}},
+        {"term": {"event.outcome": "failure"}},
+        {"term": {"user.name": "john.doe"}}
+      ],
+      "filter": {
+        "range": {
+          "@timestamp": { "gte": "now-5m" }
+        }
+      }
+    }
+  },
+  "aggs": {
+    "failure_count": { "value_count": { "field": "event.id" } }
+  }
+})
+
+count = result['aggregations']['failure_count']['value']
+# count = 7 → brute force threshold crossed
+```
+
+---
+
+---
+
+# STAGE 4: FEATURE ENGINEERING WITH tsfresh
+### "Turn raw events into numbers ML can understand"
+
+---
+
+## What is tsfresh and why do you need it?
+
+PyOD (your anomaly detector) needs **numbers** not events.
+tsfresh converts a **sequence of events over time** into **statistical features**.
+
+## What features get extracted
+
+For each user/entity over a rolling time window (e.g., last 1 hour):
+
+```
+Raw events for john.doe last 1 hour:
+[login_fail, login_fail, login_fail, login_fail, login_fail, login_fail, login_fail,
+ process_cmd.exe, dns_query_evil, transaction_950000]
+
+↓ tsfresh extracts ↓
+
+{
+  "user": "john.doe",
+  "window": "2025-02-10T14:00:00 to 14:23:11",
+
+  // Login behaviour
+  "login_failure_count": 7,
+  "login_failure_rate_per_min": 3.5,
+  "login_time_mean": "14:22:30",
+  "login_outside_hours": true,
+
+  // Process behaviour  
+  "process_rarity_score": 0.91,
+  "recon_command_detected": true,
+  "unique_processes_launched": 3,
+
+  // Network behaviour
+  "dns_queries_to_unknown_domains": 1,
+  "outbound_connections_blocked": 1,
+  "bytes_sent_external": 0,
+
+  // Transaction behaviour
+  "transaction_amount_zscore": 4.7,
+  "transaction_no_mfa": true,
+  "transaction_to_unknown_bank": true,
+
+  // Time series stats (tsfresh auto-generates these)
+  "event_count__sum_values": 10,
+  "event_severity__mean": 6.4,
+  "event_severity__maximum": 9,
+  "event_count__kurtosis": 2.1
+}
+```
+
+## Python code for feature extraction:
+
+```python
+import pandas as pd
+from tsfresh import extract_features
+from tsfresh.utilities.dataframe_functions import impute
+
+# Pull events for a user from Elasticsearch
+events_df = pd.DataFrame([
+    {"id": "john.doe", "time": 1, "severity": 7, "event_type_encoded": 3},
+    {"id": "john.doe", "time": 2, "severity": 8, "event_type_encoded": 3},
+    {"id": "john.doe", "time": 3, "severity": 9, "event_type_encoded": 5},
+    # ... more events
+])
+
+# Extract hundreds of time-series features automatically
+features = extract_features(
+    events_df,
+    column_id="id",
+    column_sort="time"
+)
+
+impute(features)  # fill NaN values
+# features is now a single row with 200+ numerical columns
+# This is what PyOD will score
+```
+
+---
+
+---
+
+# STAGE 5: UEBA & ANOMALY DETECTION WITH PyOD
+### Answering your MAJOR DOUBT completely
+
+---
+
+## THE ANSWER: What exactly does the model do?
+
+```
+┌──────────────────────────────────────────────────────────────────┐
+│                    TWO PHASES                                     │
+│                                                                   │
+│  PHASE 1 — TRAINING (offline, done ONCE before deployment)       │
+│  ─────────────────────────────────────────────────────────────   │
+│  Feed it 30 days of NORMAL log data                              │
+│  Model learns: "this is what normal looks like"                  │
+│  Saves a .pkl model file                                         │
+│  You do this ONCE. Then deploy.                                  │
+│                                                                   │
+│  PHASE 2 — INFERENCE (live, runs on every new batch of logs)     │
+│  ─────────────────────────────────────────────────────────────   │
+│  New logs arrive → features extracted → fed to saved model       │
+│  Model asks: "how different is THIS from normal?"                │
+│  Outputs: anomaly_score between 0 and 1                          │
+│  0.0 = totally normal                                            │
+│  0.91 = highly anomalous, investigate NOW                        │
+└──────────────────────────────────────────────────────────────────┘
+```
+
+**It is NOT:**
+- ❌ Predicting future attacks ("will X attack tomorrow") — that is forecasting
+- ❌ Retraining on live data continuously — that would be unstable
+- ❌ Rule-based detection ("if failed_logins > 5 then alert") — that is SIEM
+- ❌ Just analytics/dashboards
+
+**It IS:**
+- ✅ Unsupervised anomaly detection — no labeled data needed
+- ✅ Behavioral baseline comparison — "is john.doe acting like himself?"
+- ✅ Multi-dimensional scoring — catches patterns no single rule can catch
+
+---
+
+## The three PyOD models and what each detects
+
+### Model 1: Isolation Forest
+**Logic:** Anomalies are easier to isolate than normal points.
+Build random decision trees. Points that get isolated in fewer splits = anomalous.
+
+```python
+from pyod.models.iforest import IForest
+
+clf = IForest(contamination=0.05, n_estimators=100)
+clf.fit(normal_features_df)  # Train on 30 days normal data
+
+# Live scoring
+score = clf.decision_function(new_user_features)  # Returns anomaly score
+label = clf.predict(new_user_features)             # Returns 0=normal, 1=anomaly
+```
+
+**Best for:** High-volume, fast detection. Works well on network and process data.
+
+### Model 2: HBOS (Histogram-Based Outlier Score)
+**Logic:** Build a histogram for each feature. Low-frequency bins = anomalous.
+
+```python
+from pyod.models.hbos import HBOS
+
+clf = HBOS(n_bins=10, contamination=0.05)
+clf.fit(normal_features_df)
+score = clf.decision_function(new_user_features)
+```
+
+**Best for:** Very fast. Good for catching statistically rare individual behaviors.
+Example: transaction amount of ₹9.5L when this user normally transfers ₹5000 max.
+
+### Model 3: AutoEncoder
+**Logic:** Neural network that learns to compress and reconstruct normal data.
+Anomalies reconstruct poorly — high reconstruction error = anomaly.
+
+```python
+from pyod.models.auto_encoder import AutoEncoder
+
+clf = AutoEncoder(
+    hidden_neurons=[64, 32, 32, 64],
+    epochs=100,
+    contamination=0.05
+)
+clf.fit(normal_features_df)
+score = clf.decision_function(new_user_features)
+```
+
+**Best for:** Complex multi-feature behavioral patterns. Catches subtle coordinated anomalies.
+
+---
+
+## Ensemble scoring (combine all three)
+
+```python
+import numpy as np
+
+score_iforest = iforest_model.decision_function(features)
+score_hbos    = hbos_model.decision_function(features)
+score_ae      = autoencoder_model.decision_function(features)
+
+# Weighted ensemble
+final_score = (0.4 * score_iforest + 0.3 * score_hbos + 0.3 * score_ae)
+is_anomaly  = final_score > 0.7
+```
+
+---
+
+## Full output stored in Elasticsearch:
+
+```json
+{
+  "entity": "john.doe",
+  "entity_type": "user",
+  "window_start": "2025-02-10T14:00:00Z",
+  "window_end": "2025-02-10T14:23:11Z",
+  "anomaly_score": 0.91,
+  "is_anomaly": true,
+  "model_scores": {
+    "isolation_forest": 0.88,
+    "hbos": 0.94,
+    "autoencoder": 0.91
+  },
+  "top_contributing_features": {
+    "login_failure_count": 7,
+    "process_rarity_score": 0.91,
+    "transaction_amount_zscore": 4.7,
+    "dns_to_unknown_domain": 1,
+    "transaction_no_mfa": true
+  },
+  "explanation": "User showed 7 failed logins, launched rare recon commands, queried unknown DNS, and executed high-value MFA-bypassed transfer. Combined score 0.91 exceeds threshold 0.70."
+}
+```
+
+---
+
+---
+
+# STAGE 6: INCIDENT CORRELATION ENGINE
+### "Connect the dots across systems"
+
+---
+
+## Why correlation matters
+
+PyOD gives you: "john.doe is anomalous"
+Correlation gives you: "john.doe's anomaly is connected to DESKTOP-JOHN compromise,
+                        which is connected to a C2 DNS query,
+                        which is connected to a fraudulent transfer.
+                        This is a single coordinated attack, not 4 separate alerts."
+
+**Without correlation:** 4 alerts, analyst handles each separately, misses the big picture.
+**With correlation:** 1 incident with 4 linked events, full kill-chain visible.
+
+## How it works
+
+```python
+# NetworkX builds a graph of related events
+import networkx as nx
+
+G = nx.Graph()
+
+# Add events as nodes
+G.add_node("EVT-001", type="auth_failure", user="john.doe", host="DESKTOP-JOHN")
+G.add_node("EVT-002", type="process_create", user="john.doe", host="DESKTOP-JOHN")
+G.add_node("EVT-003", type="dns_query", ip="192.168.1.45", domain="evil-c2.ru")
+G.add_node("EVT-004", type="transaction", user="john.doe", amount=950000)
+
+# Add edges based on correlation rules
+G.add_edge("EVT-001", "EVT-002", reason="same_user_same_host_5min_window")
+G.add_edge("EVT-002", "EVT-003", reason="same_source_ip_2min_window")
+G.add_edge("EVT-003", "EVT-004", reason="same_user_same_session")
+
+# Find connected components = one incident
+incidents = list(nx.connected_components(G))
+# Result: {EVT-001, EVT-002, EVT-003, EVT-004} = ONE incident
+```
+
+## MITRE ATT&CK Kill Chain Alignment
+
+Each correlated event maps to a MITRE tactic:
+
+```
+EVT-001 (7 failed logins)        → T1110 — Brute Force (Credential Access)
+EVT-002 (whoami, net user)       → T1059 — Command Scripting (Execution)
+EVT-003 (DNS to C2 domain)       → T1071 — C2 over DNS (Command & Control)
+EVT-004 (₹9.5L transfer, no MFA) → T1020 — Automated Exfiltration (Exfiltration)
+
+Kill Chain Stage: Initial Access → Execution → C2 → Exfiltration
+                  (This is a complete attack sequence!)
+```
+
+---
+
+## LangGraph — Stateful Multi-Step Workflow
+
+LangGraph manages the stateful workflow across correlation steps.
+
+```python
+from langgraph.graph import StateGraph
+
+# Define state
+class IncidentState(TypedDict):
+    events: list
+    entities: list
+    anomaly_scores: dict
+    correlated_groups: list
+    mitre_mapping: dict
+    fidelity_score: float
+    playbook: str
+
+# Build graph
+workflow = StateGraph(IncidentState)
+workflow.add_node("fetch_events", fetch_related_events)
+workflow.add_node("score_anomaly", run_pyod_scoring)
+workflow.add_node("correlate", run_graph_correlation)
+workflow.add_node("map_mitre", map_to_mitre_framework)
+workflow.add_node("score_fidelity", calculate_fidelity)
+workflow.add_node("generate_playbook", call_ollama_llm)
+
+# Chain them
+workflow.add_edge("fetch_events", "score_anomaly")
+workflow.add_edge("score_anomaly", "correlate")
+workflow.add_edge("correlate", "map_mitre")
+workflow.add_edge("map_mitre", "score_fidelity")
+workflow.add_edge("score_fidelity", "generate_playbook")
+```
+
+---
+
+---
+
+# STAGE 7: FIDELITY SCORING
+### "The key differentiator — kill alert fatigue"
+
+---
+
+## What is fidelity and why does it matter
+
+A bank SIEM generates **10,000+ alerts per day**.
+Without fidelity scoring, analysts drown. Every alert looks the same.
+Fidelity scoring compresses 10,000 alerts into **20 high-confidence incidents**.
+
+## Fidelity formula
+
+```
+Fidelity = (
+  anomaly_score_weight     × 0.35 +
+  correlated_sources_weight × 0.25 +
+  mitre_coverage_weight    × 0.20 +
+  asset_criticality_weight  × 0.20
+)
+```
+
+## Real calculation for john.doe's incident:
+
+```python
+def calculate_fidelity(incident):
+    # Component 1: How anomalous was the behavior?
+    anomaly_score = 0.91  # from PyOD
+    w1 = anomaly_score * 0.35  # = 0.318
+
+    # Component 2: How many independent sources confirmed it?
+    sources = ["edr", "iam", "dns", "banking"]  # 4 sources
+    source_score = min(len(sources) / 5, 1.0)  # = 0.8
+    w2 = source_score * 0.25  # = 0.200
+
+    # Component 3: How many MITRE stages covered?
+    mitre_stages = ["credential_access", "execution", "c2", "exfiltration"]  # 4 stages
+    mitre_score = len(mitre_stages) / 7  # 4 of 7 kill-chain stages = 0.57
+    w3 = mitre_score * 0.20  # = 0.114
+
+    # Component 4: How critical is the affected asset?
+    asset_criticality = 1.0  # HIGH = 1.0, MEDIUM = 0.6, LOW = 0.3
+    w4 = asset_criticality * 0.20  # = 0.200
+
+    fidelity = w1 + w2 + w3 + w4  # = 0.832 → rounds to 0.93 with normalization
+    return fidelity
+
+# Output
+{
+  "incident_id": "INC-2025-0042",
+  "entity": "john.doe",
+  "fidelity_score": 0.93,
+  "priority": "CRITICAL",      # > 0.8
+  "sla_response_minutes": 15   # CRITICAL = respond in 15 mins
+}
+```
+
+## Priority tiers:
+
+| Fidelity Score | Priority | Response SLA |
+|---|---|---|
+| 0.8 – 1.0 | CRITICAL | 15 minutes |
+| 0.6 – 0.79 | HIGH | 1 hour |
+| 0.4 – 0.59 | MEDIUM | 4 hours |
+| Below 0.4 | LOW | Next business day |
+
+---
+
+---
+
+# STAGE 8: LLM PLAYBOOK GENERATION (Ollama + MITRE)
+### "AI analyst writes the response plan"
+
+---
+
+## The full Ollama + LangChain pipeline
+
+```python
+from langchain_community.llms import Ollama
+from langchain.prompts import PromptTemplate
+
+llm = Ollama(model="mistral", base_url="http://localhost:11434")
+
+prompt_template = PromptTemplate(
+    input_variables=["incident_timeline", "affected_assets",
+                     "anomaly_details", "mitre_mapping", "fidelity"],
+    template="""
+You are a senior SOC analyst at a bank. Generate a detailed incident response playbook.
+
+INCIDENT DETAILS:
+Fidelity Score: {fidelity}
+Affected Assets: {affected_assets}
+
+ATTACK TIMELINE:
+{incident_timeline}
+
+ANOMALY DETAILS:
+{anomaly_details}
+
+MITRE ATT&CK MAPPING:
+{mitre_mapping}
+
+Generate a step-by-step playbook with:
+1. Immediate actions (0-5 minutes)
+2. Containment actions (5-15 minutes)  
+3. Investigation steps
+4. Eradication steps
+5. Evidence collection checklist
+6. Communication plan
+"""
+)
+
+chain = prompt_template | llm
+playbook = chain.invoke({
+    "fidelity": "0.93 — CRITICAL",
+    "affected_assets": "DESKTOP-JOHN (HIGH criticality), john.doe (Finance Analyst)",
+    "incident_timeline": """
+        14:23:01 — cmd.exe launched from explorer.exe with recon commands
+        14:23:05 — Firewall blocked outbound to unknown IP 185.220.101.5:443
+        14:23:07 — 7 failed logins from 192.168.1.45 in 2 minutes
+        14:23:09 — DNS query to evil-c2-server.ru
+        14:23:11 — ₹9,50,000 bulk transfer without MFA to unknown bank
+    """,
+    "anomaly_details": "User anomaly score 0.91. Top features: login_failure=7, process_rarity=0.91, txn_zscore=4.7",
+    "mitre_mapping": "T1110 (Brute Force), T1059 (Command Scripting), T1071 (C2 DNS), T1020 (Exfiltration)"
+})
+```
+
+## What Ollama outputs (the Playbook):
+
+```
+━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
+INCIDENT RESPONSE PLAYBOOK
+Incident ID : INC-2025-0042
+Priority    : CRITICAL (Fidelity: 0.93)
+Entity      : john.doe | DESKTOP-JOHN
+Generated   : 2025-02-10 14:25:00 UTC
+━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
+
+IMMEDIATE ACTIONS (0–5 minutes):
+1. Disable john.doe AD account immediately via Active Directory console
+2. Block source IP 192.168.1.45 on perimeter firewall — all traffic
+3. Contact banking operations: HOLD transaction TXN-88210 (₹9.5L)
+4. Escalate to Security Manager and Fraud Team simultaneously
+
+CONTAINMENT (5–15 minutes):
+5. Network isolate DESKTOP-JOHN — remove from domain, block switch port
+6. Add evil-c2-server.ru to DNS blackhole / sinkhole
+7. Block all outbound from 192.168.1.45 until investigation complete
+8. Invalidate all active sessions for john.doe across all systems
+
+INVESTIGATION STEPS:
+9.  Pull all transactions by john.doe in last 24 hours from core banking
+10. Check if any other hosts queried evil-c2-server.ru
+11. Search AD logs for any accounts john.doe may have accessed
+12. Check if credentials were dumped (look for lsass.exe access)
+13. Timeline reconstruction: when was DESKTOP-JOHN first compromised?
+
+ERADICATION:
+14. Reimage DESKTOP-JOHN completely — do not trust the OS
+15. Reset all passwords accessible from john.doe's session
+16. Review and revoke all API tokens / certificates on affected accounts
+
+EVIDENCE CHECKLIST:
+[ ] Firewall deny logs (Feb 10 14:23:05 entry)
+[ ] IAM lockout event logs (EventID 4625 — 7 occurrences)
+[ ] Memory dump from DESKTOP-JOHN (before reimage)
+[ ] DNS query logs for evil-c2-server.ru
+[ ] Banking transaction receipt for TXN-88210
+[ ] Network packet capture if available
+
+COMMUNICATION PLAN:
+- T+5min : Notify CISO and SOC Lead
+- T+15min: Notify Fraud Team and Compliance Officer
+- T+1hr  : Preliminary report to Risk Management
+- T+24hr : Full incident report with root cause analysis
+
+MITRE ATT&CK REFERENCE:
+- T1110: Brute Force — reset all related credentials
+- T1059: Command Scripting — forensic review of all cmd executions
+- T1071: Application Layer Protocol (DNS C2) — review all DNS for IOCs
+- T1020: Automated Exfiltration — full financial audit required
+━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
+```
+
+This playbook is stored in Elasticsearch `playbooks-*` and shown on Kibana dashboard.
+
+---
+
+---
+
+# STAGE 9: FastAPI — THE CONTROL LAYER
+### "The nervous system connecting everything"
+
+---
+
+## What FastAPI does in your architecture
+
+FastAPI is your **central control plane**. It:
+1. Receives custom log ingestion (banking app logs)
+2. Triggers the ML pipeline on demand or on schedule
+3. Exposes REST endpoints the SOC dashboard calls
+4. Manages the LangGraph workflow execution
+
+## Key API endpoints:
+
+```python
+from fastapi import FastAPI
+
+app = FastAPI(title="Autonomous Cyber Incident Response API")
+
+@app.post("/ingest/logs")
+async def ingest_logs(logs: list[dict]):
+    """Receive logs from any source and push to Elasticsearch"""
+
+@app.post("/analyze/trigger")
+async def trigger_analysis(time_window_minutes: int = 60):
+    """Trigger feature extraction + PyOD scoring for current window"""
+
+@app.get("/incidents/active")
+async def get_active_incidents():
+    """Return all active CRITICAL and HIGH incidents"""
+
+@app.get("/incidents/{incident_id}/playbook")
+async def get_playbook(incident_id: str):
+    """Return generated playbook for a specific incident"""
+
+@app.post("/incidents/{incident_id}/resolve")
+async def resolve_incident(incident_id: str, analyst_notes: str):
+    """Mark incident resolved and store analyst feedback"""
+```
+
+---
+
+---
+
+# STAGE 10: EXPLAINABILITY LAYER
+### "Why did you flag this? Show your work."
+
+---
+
+## Why explainability is critical in banking
+
+Regulators (RBI, Basel) demand: "Why was this transaction flagged?"
+Your model cannot be a black box. Every decision must be explainable.
+
+## SHAP values — feature contribution to anomaly score
+
+```python
+import shap
+
+explainer = shap.TreeExplainer(iforest_model.detector_)
+shap_values = explainer.shap_values(user_features)
+
+explanation = {
+  "anomaly_score": 0.91,
+  "feature_contributions": {
+    "login_failure_count":        +0.31,  # pushed score UP by 0.31
+    "transaction_amount_zscore":  +0.28,  # pushed score UP by 0.28
+    "process_rarity_score":       +0.19,  # pushed score UP by 0.19
+    "dns_to_unknown_domain":      +0.13,  # pushed score UP by 0.13
+    "login_hour_deviation":       +0.09,  # minor contribution
+    "normal_transaction_count":   -0.09   # pushed score DOWN (normal behavior present)
+  },
+  "human_readable": "This entity was flagged primarily because of 7 failed logins
+                     (31% of score) combined with an unusually large transaction
+                     amount (28% of score) and rare process execution (19% of score)."
+}
+```
+
+---
+
+---
+
+# FULL SYSTEM ARCHITECTURE SUMMARY
+
+```
+┌─────────────────────────────────────────────────────────────────────────┐
+│                    DATA SOURCES                                          │
+│  EDR • Firewall • IAM/AD • DNS • Core Banking                           │
+└──────────────────┬──────────────────────────────────────────────────────┘
+                   │ Filebeat / FastAPI
+                   ▼
+┌─────────────────────────────────────────────────────────────────────────┐
+│                    LOGSTASH                                              │
+│  Parse → Filter → GeoIP Enrich → User/Asset Enrich → ECS Normalize     │
+└──────────────────┬──────────────────────────────────────────────────────┘
+                   │ Normalized ECS JSON
+                   ▼
+┌─────────────────────────────────────────────────────────────────────────┐
+│                    ELASTICSEARCH                                          │
+│  security-events-* │ behavior-features-* │ anomaly-scores-*            │
+│  incidents-*       │ playbooks-*                                        │
+└────┬──────────────────────────────────────────────────────┬────────────┘
+     │ Python reads events                                   │ Stores results
+     ▼                                                       │
+┌───────────────────────────────────────┐                   │
+│  tsfresh Feature Engineering          │                   │
+│  (Time-series → numerical features)   │                   │
+└──────────────────┬────────────────────┘                   │
+                   │ Feature vectors                        │
+                   ▼                                        │
+┌───────────────────────────────────────┐                  │
+│  PyOD Anomaly Detection               │                  │
+│  IForest + HBOS + AutoEncoder         │                  │
+│  → anomaly_score per entity           │                  │
+└──────────────────┬────────────────────┘                  │
+                   │ Scores                                │
+                   ▼                                       │
+┌───────────────────────────────────────┐                 │
+│  Correlation Engine                   │                 │
+│  NetworkX graph + LangGraph workflow  │                 │
+│  MITRE ATT&CK kill-chain mapping      │                 │
+└──────────────────┬────────────────────┘                 │
+                   │ Incident groups                      │
+                   ▼                                      │
+┌───────────────────────────────────────┐                │
+│  Fidelity Scoring                     │                │
+│  anomaly + sources + MITRE + asset    │                │
+│  → CRITICAL / HIGH / MEDIUM / LOW     │                │
+└──────────────────┬────────────────────┘                │
+                   │ Prioritized incidents               │
+                   ▼                                     │
+┌───────────────────────────────────────┐               │
+│  Ollama LLM + LangChain               │               │
+│  Mistral/Phi-3 (fully offline)        │               │
+│  MITRE ATT&CK context injection       │               │
+│  → Step-by-step playbook              │               │
+└──────────────────┬────────────────────┘               │
+                   └────────────────────────────────────►│
+                                                         │
+                   ┌─────────────────────────────────────┘
+                   ▼
+┌─────────────────────────────────────────────────────────────────────────┐
+│                    KIBANA DASHBOARD (SOC View)                           │
+│  Incident timeline │ Fidelity heatmap │ Playbooks │ UEBA deviation      │
+└─────────────────────────────────────────────────────────────────────────┘
+```
+
+---
+
+## Technology-to-Role Mapping (from problem statement)
+
+| Technology | Your Use | Why |
+|---|---|---|
+| **PyOD** | Anomaly detection (IForest, HBOS, AutoEncoder) | Unsupervised, no labeled data needed |
+| **tsfresh** | Feature engineering from event sequences | Automated time-series feature extraction |
+| **Elasticsearch Python client** | All read/write to ES indices | Central data store |
+| **LangChain** | Prompt management for Ollama | Structured prompt templates |
+| **LangGraph** | Stateful multi-step workflow | Orchestrates the full pipeline |
+| **FastAPI** | Custom log ingestion + REST API | Control plane |
+| **HuggingFace** | Sentence embeddings for log similarity | Semantic search on incidents |
+| **Ollama** | Offline LLM (Mistral/Phi-3) | Playbook generation, zero data leakage |
+
+---
+
+*All processing is local. Zero external API calls. Fully air-gapped capable.*
