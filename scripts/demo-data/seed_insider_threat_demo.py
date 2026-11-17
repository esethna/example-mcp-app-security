#!/usr/bin/env python3
"""
Seed Elastic with demo data for the "departing cleared contractor" insider threat scenario.

Story: Elliot Marsh (e.marsh), a cleared contractor on the AURORA program, resigned six days
ago. At 22:41 facility time he badges back into the secure facility, signs in at 22:52, opens
documents from KESTREL (a program he has never worked on) and at 23:40 prints 340 pages of
them. One Elastic rule, "Large print job outside working hours", raises the alert. The other
signals (badge, sign-in, file opens, HR record, access roster) sit in Elastic for the agent to
find and correlate.

What it creates
  - Index template  demo-insider  (ECS-style mappings plus print.* and classification.*)
  - Data streams    90 days of weekday baseline for 12 staff, plus the incident night
      logs-pacs.insider-default   badge readers (physical access control)
      logs-sso.insider-default    workstation sign-ins
      logs-uam.insider-default    user activity monitoring: file opens, print jobs, USB
  - Lookup indices
      hr-departing-staff          HR feed of resignations and last working days
      security-access-roster      clearance and program access per person
  - Detection rules (Kibana Detection Engine API), tagged demo:insider-threat
      1. Large print job outside working hours         (ES|QL, high)   <- the demo alert
      2. Multiple failed sign-ins for a user           (ES|QL, medium) noise
      3. Removable media on a classified workstation   (query, low)    noise

Times
  The incident is placed on the most recent night whose 23:40 (facility time) has passed, so
  seed on the day of a demo or recording. Facility time zone: DEMO_TZ (default
  America/Regina, UTC-6 with no daylight saving). Rules look back 40h so the alerts fire on
  their first run after seeding.

Usage
  export ELASTIC_API_KEY=...            # encoded API key (the value used in "ApiKey <key>")
  export ES_URL=https://es.local:9200
  export KIBANA_URL=https://kibana.local:5601
  export KIBANA_SPACE=default           # optional
  export DEMO_TZ=America/Regina         # optional; facility time zone (pick one without DST)
  export ES_CA_CERT=/path/ca.crt        # optional; or ES_INSECURE=1 to skip TLS verification

  These can also be set in a .env file next to this script (exported variables take precedence).

  python3 seed_insider_threat_demo.py                  # (re)seed events, lookups + rules
  python3 seed_insider_threat_demo.py --wait-alerts 10 # ...then poll up to 10 min for alerts
  python3 seed_insider_threat_demo.py --no-rules       # data only
  python3 seed_insider_threat_demo.py --incident-date 2026-11-18   # pin the incident night
  python3 seed_insider_threat_demo.py --reset          # remove rules, alerts, data, template
  python3 seed_insider_threat_demo.py --dry-run        # generate locally, no network

Privileges the API key needs (use a separate, narrower key for the MCP app)
  Elasticsearch
    cluster: manage_index_templates
    indices logs-pacs.insider-*, logs-sso.insider-*, logs-uam.insider-*:
            create_index, create_doc, auto_configure, read, delete_index
    indices hr-departing-staff, security-access-roster: create_index, index, read, delete_index
    indices .alerts-security.alerts-*: read, delete   (for --wait-alerts and --reset)
  Kibana
    Security > Rules (All) in the target space
"""

import argparse
import json
import os
import random
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

DEMO_TAG = "insider-threat"
PACS_DS = "logs-pacs.insider-default"
SSO_DS = "logs-sso.insider-default"
UAM_DS = "logs-uam.insider-default"
DATA_STREAMS = (PACS_DS, SSO_DS, UAM_DS)
HR_INDEX = "hr-departing-staff"
ROSTER_INDEX = "security-access-roster"
LOOKUP_INDICES = (HR_INDEX, ROSTER_INDEX)
TEMPLATE = "demo-insider"
RANDOM_SEED = 1119
BASELINE_DAYS = 90
# No daylight saving, so a fixed UTC offset in ES|QL queries is correct for the whole baseline.
DEFAULT_TZ = "America/Regina"

# (user.name, full name, employer, programs, workstation)
SUBJECT = ("e.marsh", "Elliot Marsh", "Halvorsen Systems", ["AURORA"], "WS-0142")
STAFF = [
    ("a.okafor", "Adaeze Okafor", "Government", ["AURORA"], "WS-0137"),
    ("j.whitlock", "James Whitlock", "Government", ["AURORA", "TALON"], "WS-0139"),
    ("m.duval", "Marie Duval", "Halvorsen Systems", ["AURORA"], "WS-0144"),
    ("s.kaur", "Simran Kaur", "Government", ["KESTREL"], "WS-0151"),
    ("d.reyes", "Daniel Reyes", "Government", ["KESTREL"], "WS-0153"),
    ("l.becker", "Lena Becker", "Northgate Analytics", ["KESTREL", "TALON"], "WS-0155"),
    ("k.osei", "Kwame Osei", "Government", ["TALON"], "WS-0160"),
    ("p.lindqvist", "Petra Lindqvist", "Government", ["TALON"], "WS-0162"),
    ("r.nakamura", "Ren Nakamura", "Northgate Analytics", ["AURORA"], "WS-0146"),
    ("c.moreau", "Claire Moreau", "Government", ["KESTREL"], "WS-0157"),
    ("t.brennan", "Thomas Brennan", "Government", ["TALON", "AURORA"], "WS-0164"),
]
PEOPLE = [SUBJECT] + STAFF

PROGRAM_DOCS = {
    "AURORA": ["AURORA_sensor_calibration_notes.docx", "AURORA_weekly_status.pptx",
               "AURORA_integration_test_plan.pdf", "AURORA_requirements_v4.docx",
               "AURORA_field_trial_results.xlsx", "AURORA_interface_spec.pdf"],
    "KESTREL": ["KESTREL_program_review_pack.pdf", "KESTREL_capability_overview.pptx",
                "KESTREL_threat_assessment_2026.pdf", "KESTREL_source_register.xlsx",
                "KESTREL_deployment_schedule.docx", "KESTREL_vulnerability_findings.pdf",
                "KESTREL_partner_access_list.xlsx", "KESTREL_technical_annex_B.pdf"],
    "TALON": ["TALON_logistics_plan.docx", "TALON_budget_q4.xlsx",
              "TALON_site_survey.pdf", "TALON_ops_brief.pptx"],
}
MARKINGS = {"AURORA": "TS//SCI", "KESTREL": "TS//SCI//NOFORN", "TALON": "SECRET//NOFORN"}
SHARE = "\\\\fs-scif-01\\programs"
PRINTERS = {"AURORA": "PRN-SCIF-02", "KESTREL": "PRN-SCIF-03", "TALON": "PRN-SCIF-01"}
BADGE_READER_IN = ("B7-SCIF-MAIN-IN", "Building 7 SCIF main entrance")
BADGE_READER_OUT = ("B7-SCIF-MAIN-OUT", "Building 7 SCIF main entrance")

RULE_IDS = {
    "print": "demo-insider-after-hours-print",
    "failed": "demo-insider-failed-signins",
    "usb": "demo-insider-removable-media",
}


# --------------------------------------------------------------------------- HTTP

def system_ca_bundle():
    """python.org builds on macOS ship without trusted CAs; fall back to the OS bundle."""
    cafile = ssl.get_default_verify_paths().cafile
    if cafile and os.path.exists(cafile):
        return None
    return "/etc/ssl/cert.pem" if os.path.exists("/etc/ssl/cert.pem") else None


class Client:
    def __init__(self, es_url, kb_url, api_key, space, ca_cert=None, insecure=False):
        self.es_url = es_url.rstrip("/")
        self.kb_url = kb_url.rstrip("/")
        self.api_key = api_key
        self.space = space
        self.space_prefix = "" if space == "default" else f"/s/{space}"
        if insecure:
            self.ctx = ssl._create_unverified_context()
        else:
            self.ctx = ssl.create_default_context(cafile=ca_cert or system_ca_bundle())

    def _req(self, method, url, body=None, headers=None, ndjson=False):
        h = {"Authorization": f"ApiKey {self.api_key}"}
        data = None
        if body is not None:
            if ndjson:
                data = body.encode("utf-8")
                h["Content-Type"] = "application/x-ndjson"
            else:
                data = json.dumps(body).encode("utf-8")
                h["Content-Type"] = "application/json"
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=120) as r:
                status, raw = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        except urllib.error.URLError as e:
            sys.exit(f"ERROR: cannot reach {url}: {e.reason}")
        try:
            parsed = json.loads(raw) if raw else {}
        except ValueError:
            parsed = {"raw": raw.decode("utf-8", errors="replace")[:500]}
        return status, parsed

    def es(self, method, path, body=None, ndjson=False):
        return self._req(method, self.es_url + path, body, ndjson=ndjson)

    def kb(self, method, path, body=None):
        headers = {"kbn-xsrf": "true", "elastic-api-version": "2023-10-31"}
        return self._req(method, f"{self.kb_url}{self.space_prefix}{path}", body, headers=headers)


def fail(msg, body=None):
    print(f"ERROR: {msg}", file=sys.stderr)
    if body is not None:
        print(json.dumps(body, indent=2)[:2000], file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------- data

def iso(ts):
    return ts.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def at(day, hour, minute, tz, second=0):
    return datetime(day.year, day.month, day.day, hour, minute, second, tzinfo=tz)


def person(username):
    return next(p for p in PEOPLE if p[0] == username)


def ws_ip(ws):
    return f"10.70.1.{int(ws.split('-')[1]) % 250}"


def event(ts, *, dataset, module, category, etype, action, outcome, who, message, **extra):
    user, full_name = who[0], who[1]
    doc = {
        "@timestamp": iso(ts),
        "message": message,
        "event": {"kind": "event", "category": category, "type": etype, "action": action,
                  "outcome": outcome, "dataset": dataset, "module": module},
        "user": {"name": user, "full_name": full_name},
        "labels": {"demo": DEMO_TAG},
    }
    doc.update(extra)
    return doc


def badge(ts, who, direction):
    reader, door = BADGE_READER_IN if direction == "in" else BADGE_READER_OUT
    return (PACS_DS, event(
        ts, dataset="pacs.badge", module="pacs", category="authentication",
        etype="start" if direction == "in" else "end", action=f"badge_{direction}",
        outcome="success", who=who,
        message=f"Badge {direction} for {who[1]} ({who[0]}) at {door}",
        observer={"vendor": "PACS", "product": "Badge reader"},
        pacs={"reader": reader, "door": door}))


def signin(ts, who, outcome="success", note=""):
    ws = who[4]
    verb = "succeeded" if outcome == "success" else "failed"
    return (SSO_DS, event(
        ts, dataset="sso.logon", module="sso", category="authentication", etype="start",
        action="logon", outcome=outcome, who=who,
        message=f"Workstation sign-in {verb} for {who[0]} on {ws}{note}",
        host={"name": ws}, source={"ip": ws_ip(ws)}))


def file_open(ts, who, program, doc_name):
    return (UAM_DS, event(
        ts, dataset="uam.activity", module="uam", category="file", etype="access",
        action="file_open", outcome="success", who=who,
        message=f"{who[0]} opened {doc_name} on {who[4]}",
        host={"name": who[4]},
        file={"name": doc_name, "path": f"{SHARE}\\{program}\\{doc_name}"},
        classification={"marking": MARKINGS[program], "program": program},
        observer={"vendor": "UAM", "product": "User activity monitoring"}))


def print_job(ts, who, program, doc_name, pages, job_id, printer=None):
    printer = printer or PRINTERS[program]
    return (UAM_DS, event(
        ts, dataset="uam.activity", module="uam", category="file", etype="info",
        action="print", outcome="success", who=who,
        message=f"{who[0]} printed {pages} pages of {doc_name} ({MARKINGS[program]}) on {printer}",
        host={"name": who[4]},
        file={"name": doc_name, "path": f"{SHARE}\\{program}\\{doc_name}"},
        print={"printer": printer, "pages": pages, "job_id": job_id},
        classification={"marking": MARKINGS[program], "program": program},
        observer={"vendor": "UAM", "product": "User activity monitoring"}))


def usb_mount(ts, who, device_id, model):
    return (UAM_DS, event(
        ts, dataset="uam.activity", module="uam", category="host", etype="change",
        action="usb_mount", outcome="success", who=who,
        message=f"Removable media {model} ({device_id}) mounted on {who[4]} by {who[0]}",
        host={"name": who[4]},
        device={"id": device_id, "model": {"name": model}},
        observer={"vendor": "UAM", "product": "User activity monitoring"}))


class JobIds:
    def __init__(self):
        self.n = 3200

    def next(self):
        self.n += 1
        return f"PJ-{self.n}"


def normal_day(docs, rng, day, who, tz, jobs, leave_by=None):
    """A weekday in the office: badge in 07:00-08:45, out 16:00-18:15, own programs only."""
    badge_in = at(day, 7, 0, tz) + timedelta(minutes=rng.randint(0, 105))
    badge_out = at(day, 16, 0, tz) + timedelta(minutes=rng.randint(0, 135))
    if leave_by:
        badge_out = min(badge_out, leave_by)
    logon = badge_in + timedelta(minutes=rng.randint(4, 18))
    docs += [badge(badge_in, who, "in"), signin(logon, who)]

    window_start = logon + timedelta(minutes=10)
    window = int((badge_out - window_start).total_seconds() // 60) - 15
    for _ in range(rng.randint(2, 6)):
        program = rng.choice(who[3])
        docs.append(file_open(window_start + timedelta(minutes=rng.randint(0, window)),
                              who, program, rng.choice(PROGRAM_DOCS[program])))
    for _ in range(rng.choices([0, 1, 2], weights=[35, 50, 15])[0]):
        program = rng.choice(who[3])
        docs.append(print_job(window_start + timedelta(minutes=rng.randint(0, window)),
                              who, program, rng.choice(PROGRAM_DOCS[program]),
                              rng.randint(1, 12), jobs.next()))
    docs.append(badge(badge_out, who, "out"))


def incident_night(docs, rng, day, tz):
    who = SUBJECT
    docs.append(badge(at(day, 22, 41, tz, 12), who, "in"))
    docs.append(signin(at(day, 22, 52, tz, 40), who))
    t = at(day, 23, 2, tz, 5)
    for doc_name in PROGRAM_DOCS["KESTREL"] + rng.sample(PROGRAM_DOCS["KESTREL"], 6):
        docs.append(file_open(t, who, "KESTREL", doc_name))
        t += timedelta(minutes=2, seconds=rng.randint(0, 40))
    docs.append(print_job(at(day, 23, 40, tz, 5), who, "KESTREL",
                          "KESTREL_program_review_pack.pdf", 340, "PJ-4471",
                          printer=PRINTERS["AURORA"]))


def noise(docs, day, tz):
    """Unrelated alerts on the incident day, so the agent has to pick out what matters."""
    k = person("k.osei")
    for i in range(6):
        docs.append(signin(at(day, 14, 5, tz, 10) + timedelta(seconds=35 * i), k, "failure",
                           " (bad password)"))
    docs.append(signin(at(day, 14, 12, tz, 30), k, note=" after password reset by service desk"))
    p = person("p.lindqvist")
    docs.append(usb_mount(at(day, 13, 10, tz, 44), p, "USB-AUTH-0093",
                          "Encrypted USB (authorized media)"))


def build_events(day, tz, rng):
    docs, jobs = [], JobIds()
    for days_ago in range(BASELINE_DAYS, 0, -1):
        d = day - timedelta(days=days_ago)
        if d.weekday() >= 5:
            continue
        for who in PEOPLE:
            normal_day(docs, rng, d, who, tz, jobs)

    if day.weekday() < 5:
        for who in PEOPLE:
            leave_by = at(day, 17, 10, tz) if who is SUBJECT else None
            normal_day(docs, rng, day, who, tz, jobs, leave_by=leave_by)
        noise(docs, day, tz)
    incident_night(docs, rng, day, tz)
    return docs


def add_working_days(d, n):
    while n:
        d += timedelta(days=1)
        if d.weekday() < 5:
            n -= 1
    return d


def build_lookups(day, tz):
    recorded = at(day - timedelta(days=6), 10, 15, tz)
    hr = [
        {"@timestamp": iso(recorded), "user": {"name": SUBJECT[0], "full_name": SUBJECT[1]},
         "hr": {"status": "resigned", "employment_type": "contractor", "employer": SUBJECT[2],
                "notice_date": (day - timedelta(days=6)).isoformat(),
                "last_working_day": add_working_days(day, 8).isoformat(),
                "reason": "Accepted external offer"},
         "labels": {"demo": DEMO_TAG}},
        {"@timestamp": iso(at(day - timedelta(days=21), 9, 40, tz)),
         "user": {"name": "t.brennan", "full_name": "Thomas Brennan"},
         "hr": {"status": "retiring", "employment_type": "employee", "employer": "Government",
                "notice_date": (day - timedelta(days=21)).isoformat(),
                "last_working_day": add_working_days(day, 25).isoformat(),
                "reason": "Retirement"},
         "labels": {"demo": DEMO_TAG}},
    ]
    roster = [
        {"user": {"name": u, "full_name": n},
         "roster": {"clearance": "TS/SCI", "programs": programs, "employer": employer,
                    "employment_type": "employee" if employer == "Government" else "contractor",
                    "workstation": ws, "shift": "day"},
         "labels": {"demo": DEMO_TAG}}
        for u, n, employer, programs, ws in PEOPLE
    ]
    return hr, roster


# --------------------------------------------------------------------------- mappings

KW = {"type": "keyword"}
USER_PROPS = {"name": KW, "full_name": KW}
TEMPLATE_BODY = {
    "index_patterns": ["logs-pacs.insider-*", "logs-sso.insider-*", "logs-uam.insider-*"],
    "data_stream": {},
    "priority": 500,
    "_meta": {"description": "Insider threat demo data", "demo": DEMO_TAG},
    "template": {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "message": {"type": "text"},
                "event": {"properties": {k: KW for k in
                                         ("kind", "category", "type", "action", "outcome",
                                          "dataset", "module")}},
                "user": {"properties": USER_PROPS},
                "host": {"properties": {"name": KW}},
                "source": {"properties": {"ip": {"type": "ip"}}},
                "file": {"properties": {"name": KW, "path": KW}},
                "print": {"properties": {"printer": KW, "pages": {"type": "long"},
                                         "job_id": KW}},
                "classification": {"properties": {"marking": KW, "program": KW}},
                "device": {"properties": {"id": KW, "model": {"properties": {"name": KW}}}},
                "pacs": {"properties": {"reader": KW, "door": KW}},
                "observer": {"properties": {"vendor": KW, "product": KW}},
                "labels": {"properties": {"demo": KW}},
            }
        }
    },
}
LOOKUP_MAPPINGS = {
    HR_INDEX: {"properties": {
        "@timestamp": {"type": "date"},
        "user": {"properties": USER_PROPS},
        "hr": {"properties": {"status": KW, "employment_type": KW, "employer": KW,
                              "notice_date": {"type": "date"},
                              "last_working_day": {"type": "date"}, "reason": KW}},
        "labels": {"properties": {"demo": KW}},
    }},
    ROSTER_INDEX: {"properties": {
        "user": {"properties": USER_PROPS},
        "roster": {"properties": {"clearance": KW, "programs": KW, "employer": KW,
                                  "employment_type": KW, "workstation": KW, "shift": KW}},
        "labels": {"properties": {"demo": KW}},
    }},
}


# --------------------------------------------------------------------------- rules

def mitre(tactic_id, tactic_name, tech_id, tech_name):
    return [{
        "framework": "MITRE ATT&CK",
        "tactic": {"id": tactic_id, "name": tactic_name,
                   "reference": f"https://attack.mitre.org/tactics/{tactic_id}/"},
        "technique": [{"id": tech_id, "name": tech_name,
                       "reference": f"https://attack.mitre.org/techniques/{tech_id}/",
                       "subtechnique": []}],
    }]


COMMON = {"enabled": True, "interval": "5m", "from": "now-40h", "max_signals": 100,
          "tags": ["demo:insider-threat", "Insider Threat"]}
SUPPRESS_BY_USER = {"group_by": ["user.name"], "duration": {"value": 48, "unit": "h"},
                    "missing_fields_strategy": "suppress"}


def to_local(offset_minutes):
    sign = "+" if offset_minutes >= 0 else "-"
    return f"@timestamp {sign} {abs(offset_minutes)} minutes"


def build_rules(offset_minutes):
    return [
        {**COMMON,
         "rule_id": RULE_IDS["print"],
         "name": "Large print job outside working hours",
         "description": "A print job of more than 100 pages was sent outside facility working "
                        "hours (07:00-19:00 local time).",
         "type": "esql", "language": "esql",
         "query": (
             "FROM logs-uam.insider-* METADATA _id, _index, _version\n"
             "| WHERE event.action == \"print\" AND print.pages > 100\n"
             f"| EVAL local_hour = DATE_EXTRACT(\"hour_of_day\", {to_local(offset_minutes)})\n"
             "| WHERE local_hour < 7 OR local_hour >= 19\n"
             "| KEEP _id, _index, _version, @timestamp, user.name, user.full_name, host.name,\n"
             "       print.printer, print.pages, print.job_id, file.name,\n"
             "       classification.marking, classification.program"),
         "severity": "high", "risk_score": 73,
         "threat": mitre("TA0009", "Collection", "T1039", "Data from Network Shared Drive"),
         "alert_suppression": SUPPRESS_BY_USER},
        {**COMMON,
         "rule_id": RULE_IDS["failed"],
         "name": "Multiple failed sign-ins for a user",
         "description": "Five or more failed workstation sign-ins for one user.",
         "type": "esql", "language": "esql",
         "query": (
             "FROM logs-sso.insider-*\n"
             "| WHERE event.action == \"logon\" AND event.outcome == \"failure\"\n"
             "| STATS failures = COUNT(*), hosts = VALUES(host.name),\n"
             "        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY user.name\n"
             "| WHERE failures >= 5"),
         "severity": "medium", "risk_score": 47,
         "threat": mitre("TA0006", "Credential Access", "T1110", "Brute Force"),
         "alert_suppression": SUPPRESS_BY_USER},
        {**COMMON,
         "rule_id": RULE_IDS["usb"],
         "name": "Removable media mounted on a classified workstation",
         "description": "A removable storage device was mounted on a workstation in the secure "
                        "facility.",
         "type": "query", "language": "kuery",
         "index": ["logs-uam.insider-*"],
         "query": "event.action:\"usb_mount\"",
         "severity": "low", "risk_score": 21,
         "threat": mitre("TA0010", "Exfiltration", "T1052", "Exfiltration Over Physical Medium")},
    ]


def rule_path(rule_id):
    return "/api/detection_engine/rules?rule_id=" + urllib.parse.quote(rule_id)


def upsert_rules(c, rules):
    for rule in rules:
        c.kb("DELETE", rule_path(rule["rule_id"]))  # 404 is fine
        st, body = c.kb("POST", "/api/detection_engine/rules", rule)
        if st >= 300 and "alert_suppression" in rule:
            print(f"  ! '{rule['name']}' rejected with alert_suppression "
                  f"({body.get('message', st)}); retrying without it")
            rule = {k: v for k, v in rule.items() if k != "alert_suppression"}
            st, body = c.kb("POST", "/api/detection_engine/rules", rule)
        if st >= 300:
            fail(f"creating rule '{rule['name']}' failed (HTTP {st})", body)
        print(f"  + rule  {rule['rule_id']}  (id {body.get('id')})")


# --------------------------------------------------------------------------- actions

def alerts_index(c):
    return f".alerts-security.alerts-{c.space}"


def bulk(c, docs, op, batch=1000):
    for i in range(0, len(docs), batch):
        lines = []
        for index, doc in docs[i:i + batch]:
            lines.append(json.dumps({op: {"_index": index}}))
            lines.append(json.dumps(doc))
        st, body = c.es("POST", "/_bulk?refresh=wait_for", "\n".join(lines) + "\n", ndjson=True)
        if st >= 300:
            fail(f"bulk request failed (HTTP {st})", body)
        if body.get("errors"):
            errs = [it[op]["error"] for it in body["items"] if "error" in it.get(op, {})]
            fail(f"{len(errs)} documents rejected in batch starting at {i}", errs[:3])


def delete_data(c):
    for ds in DATA_STREAMS:
        st, body = c.es("DELETE", f"/_data_stream/{ds}")
        if st not in (200, 404):
            fail(f"deleting data stream {ds} failed (HTTP {st})", body)
    for index in LOOKUP_INDICES:
        st, body = c.es("DELETE", f"/{index}")
        if st not in (200, 404):
            fail(f"deleting index {index} failed (HTTP {st})", body)


def create_lookup_index(c, index):
    body = {"settings": {"index": {"mode": "lookup"}}, "mappings": LOOKUP_MAPPINGS[index]}
    st, resp = c.es("PUT", f"/{index}", body)
    if st >= 300:
        print(f"  ! lookup mode rejected for {index} ({resp.get('error', {}).get('reason', st)});"
              " creating a standard index")
        st, resp = c.es("PUT", f"/{index}", {"mappings": LOOKUP_MAPPINGS[index]})
    if st >= 300:
        fail(f"creating index {index} failed (HTTP {st})", resp)


def resolve_day(tz, override):
    if override:
        return date.fromisoformat(override)
    now = datetime.now(tz)
    day = now.date()
    if now < at(day, 23, 41, tz):
        day -= timedelta(days=1)
    return day


def offset_minutes(day, tz):
    return int(at(day, 23, 40, tz).utcoffset().total_seconds() // 60)


def seed(c, day, tz, with_rules, wait_minutes):
    st, me = c.es("GET", "/_security/_authenticate")
    if st >= 300:
        fail("API key rejected by Elasticsearch", me)
    print(f"Authenticated as {me.get('username')} "
          f"(api key: {me.get('api_key', {}).get('name', 'n/a')})")
    print(f"Incident night: {day.isoformat()} ({tz.key})")

    docs = build_events(day, tz, random.Random(RANDOM_SEED))
    hr, roster = build_lookups(day, tz)

    print("Removing previous demo data (alerts are kept; use --reset for those)")
    delete_data(c)

    st, body = c.es("PUT", f"/_index_template/{TEMPLATE}", TEMPLATE_BODY)
    if st >= 300:
        fail("creating index template failed", body)
    print(f"  + template {TEMPLATE}")

    bulk(c, docs, "create")
    for ds in DATA_STREAMS:
        print(f"  + {sum(1 for i, _ in docs if i == ds):5} events -> {ds}")

    for index, rows in ((HR_INDEX, hr), (ROSTER_INDEX, roster)):
        create_lookup_index(c, index)
        bulk(c, [(index, r) for r in rows], "index")
        print(f"  + {len(rows):5} records -> {index}")

    if with_rules:
        upsert_rules(c, build_rules(offset_minutes(day, tz)))
        if wait_minutes:
            wait_for_alerts(c, wait_minutes)
    print(f"Done. Print job at {iso(at(day, 23, 40, tz, 5))} (23:40 {tz.key})")


def wait_for_alerts(c, minutes):
    expected = set(RULE_IDS.values())
    deadline = time.time() + minutes * 60
    query = {
        "size": 50,
        "sort": [{"@timestamp": "asc"}],
        "_source": ["@timestamp", "kibana.alert.uuid", "kibana.alert.rule.rule_id",
                    "kibana.alert.rule.name", "kibana.alert.severity", "user.name"],
        "query": {"bool": {"filter": [{"terms": {"kibana.alert.rule.rule_id": sorted(expected)}}]}},
    }
    print(f"Waiting up to {minutes} min for alerts in {alerts_index(c)} ...")
    hits = []
    while time.time() < deadline:
        st, body = c.es("POST", f"/{alerts_index(c)}/_search", query)
        hits = body.get("hits", {}).get("hits", []) if st == 200 else []
        seen = {_dig(h["_source"], "kibana.alert.rule.rule_id") for h in hits}
        if expected <= seen:
            break
        time.sleep(30)
    if not hits:
        print("  ! no alerts yet. Check the rules' execution status in Security > Rules.")
        return
    for h in hits:
        s = h["_source"]
        print(f"  * {_dig(s, 'kibana.alert.severity'):8} {_dig(s, 'user.name') or '-':12} "
              f"{_dig(s, 'kibana.alert.rule.name')}  uuid={_dig(s, 'kibana.alert.uuid')}")


def _dig(d, dotted):
    if dotted in d:
        return d[dotted]
    for part in dotted.split("."):
        if not isinstance(d, dict):
            return None
        d = d.get(part)
    return d


def reset(c):
    for rule_id in RULE_IDS.values():
        st, _ = c.kb("DELETE", rule_path(rule_id))
        print(f"  - rule {rule_id}: {'deleted' if st == 200 else 'not found' if st == 404 else st}")
    st, body = c.es(
        "POST", f"/{alerts_index(c)}/_delete_by_query?conflicts=proceed&refresh=true",
        {"query": {"terms": {"kibana.alert.rule.rule_id": sorted(RULE_IDS.values())}}})
    if st == 200:
        print(f"  - alerts deleted: {body.get('deleted', 0)}")
    elif st != 404:
        print(f"  ! could not delete alerts (HTTP {st}): {body.get('error', body)}")
    delete_data(c)
    print(f"  - data streams {', '.join(DATA_STREAMS)}")
    print(f"  - indices {', '.join(LOOKUP_INDICES)}")
    st, _ = c.es("DELETE", f"/_index_template/{TEMPLATE}")
    print(f"  - template {TEMPLATE}: {'deleted' if st == 200 else 'not found'}")
    print("Reset done. Close or delete any demo Kibana cases and Mattermost runs by hand.")


def dry_run(day, tz):
    docs = build_events(day, tz, random.Random(RANDOM_SEED))
    hr, roster = build_lookups(day, tz)
    off = offset_minutes(day, tz)
    local = lambda d: datetime.fromisoformat(d["@timestamp"].replace("Z", "+00:00")).astimezone(tz)

    print(f"Incident night: {day.isoformat()} ({tz.key}, UTC{off / 60:+g})")
    for ds in DATA_STREAMS:
        print(f"  {sum(1 for i, _ in docs if i == ds):5} events -> {ds}")
    print(f"  {len(hr):5} records -> {HR_INDEX}")
    print(f"  {len(roster):5} records -> {ROSTER_INDEX}")

    print("\nIncident night (facility time):")
    night = [d for _, d in docs if d["user"]["name"] == SUBJECT[0] and local(d).date() == day
             and local(d).hour >= 19]
    for d in night:
        print(f"  {local(d):%H:%M:%S}  {d['event']['action']:10} {d['message']}")

    print("\nWhat the print rule matches (>100 pages outside 07:00-19:00):")
    for _, d in docs:
        if d["event"]["action"] == "print" and d["print"]["pages"] > 100 \
                and not 7 <= local(d).hour < 19:
            print(f"  {local(d):%Y-%m-%d %H:%M}  {d['user']['name']}  {d['print']['pages']} pages  "
                  f"{d['classification']['marking']}  {d['file']['name']}")

    base = [d for _, d in docs if d["user"]["name"] == SUBJECT[0] and local(d).date() < day]
    prints = [d for d in base if d["event"]["action"] == "print"]
    workdays = len({local(d).date() for d in base})
    latest = max(local(d).strftime("%H:%M") for d in base)
    print(f"\n{SUBJECT[0]} baseline ({BASELINE_DAYS} days, {workdays} workdays):")
    print(f"  latest activity of any day: {latest}")
    print(f"  pages printed per workday:  {sum(d['print']['pages'] for d in prints) / workdays:.1f}")
    print(f"  largest print job:          {max(d['print']['pages'] for d in prints)} pages")
    print(f"  programs accessed:          "
          f"{sorted({d['classification']['program'] for d in base if 'classification' in d})}")

    print("\nNoise on the incident day:")
    for _, d in docs:
        if d["user"]["name"] in ("k.osei", "p.lindqvist") and local(d).date() == day \
                and (d["event"]["outcome"] == "failure" or d["event"]["action"] == "usb_mount"):
            print(f"  {local(d):%H:%M:%S}  {d['message']}")

    print("\nHR departing staff:")
    for r in hr:
        print(f"  {r['user']['name']:10} {r['hr']['status']:9} notice {r['hr']['notice_date']}  "
              f"last day {r['hr']['last_working_day']}")

    print("\nPrint rule query:")
    print("  " + build_rules(off)[0]["query"].replace("\n", "\n  "))


# --------------------------------------------------------------------------- main

ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def load_dotenv(path=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")):
    """Load KEY=VALUE pairs from .env next to this script; already-set variables win."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return
    for line in lines:
        m = ENV_LINE.match(line)
        if not m or line.lstrip().startswith("#"):
            continue
        key, value = m.groups()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        else:
            value = re.sub(r"\s+#.*$", "", value)
        os.environ.setdefault(key, value)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reset", action="store_true", help="remove everything this script created")
    ap.add_argument("--no-rules", action="store_true", help="seed data only")
    ap.add_argument("--wait-alerts", type=int, metavar="MIN", default=0,
                    help="after seeding, poll up to MIN minutes for the demo alerts")
    ap.add_argument("--incident-date", metavar="YYYY-MM-DD",
                    help="night of the incident (default: most recent night whose 23:40 has passed)")
    ap.add_argument("--dry-run", action="store_true", help="generate locally and summarise; no network")
    args = ap.parse_args()
    load_dotenv()

    tz = ZoneInfo(os.environ.get("DEMO_TZ", DEFAULT_TZ))
    day = resolve_day(tz, args.incident_date)

    if args.dry_run:
        dry_run(day, tz)
        return

    missing = [v for v in ("ELASTIC_API_KEY", "ES_URL", "KIBANA_URL") if not os.environ.get(v)]
    if missing:
        fail(f"missing environment variables: {', '.join(missing)}")
    c = Client(os.environ["ES_URL"], os.environ["KIBANA_URL"], os.environ["ELASTIC_API_KEY"],
               os.environ.get("KIBANA_SPACE", "default"),
               ca_cert=os.environ.get("ES_CA_CERT"),
               insecure=os.environ.get("ES_INSECURE") == "1")

    if args.reset:
        reset(c)
    else:
        seed(c, day, tz, with_rules=not args.no_rules, wait_minutes=args.wait_alerts)


if __name__ == "__main__":
    main()
