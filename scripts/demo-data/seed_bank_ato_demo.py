#!/usr/bin/env python3
"""
Seed Elastic with demo data for the "compromised bank employee account" scenario.

Story: Northbridge Bank employee m.kovac logs in from the Sofia office, then ~20 min
later from Sao Paulo (impossible travel, after several denied MFA pushes), and the
foreign session bulk-reads and exports customer records from other branches.

What it creates
  - Index template  demo-bank-ato  (explicit ECS-style mappings)
  - Data streams    logs-auth.demo-default, logs-app.demo-default
      * 14 days of baseline activity for 13 employees (weekdays, Sofia office)
      * today's normal activity + the attack timeline, relative to "now"
  - Detection rules (Kibana Detection Engine API), tagged demo:bank-ato
      1. Impossible travel            (ES|QL, high)
      2. Bulk customer data access    (ES|QL, critical)
      3. First login from new country (new terms, medium)

Usage
  export ELASTIC_API_KEY=...            # encoded API key (the value used in "ApiKey <key>")
  export ES_URL=https://es.local:9200
  export KIBANA_URL=https://kibana.local:5601
  export KIBANA_SPACE=default           # optional
  export ES_CA_CERT=/path/ca.crt        # optional; or ES_INSECURE=1 to skip TLS verification

  These can also be set in a .env file next to this script (exported variables take precedence).

  python3 seed_bank_ato_demo.py                 # (re)seed events + rules
  python3 seed_bank_ato_demo.py --wait-alerts 10  # ...then poll up to 10 min for alerts
  python3 seed_bank_ato_demo.py --no-rules      # events only
  python3 seed_bank_ato_demo.py --reset         # remove rules, alerts, data streams, template
  python3 seed_bank_ato_demo.py --dry-run       # generate locally, no network

Privileges the API key needs (use a separate, narrower key for the MCP app)
  Elasticsearch
    cluster: manage_index_templates
    indices logs-auth.demo-*, logs-app.demo-*: create_index, create_doc, auto_configure,
            read, delete_index
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
from datetime import datetime, timedelta, timezone

DEMO_TAG = "bank-ato"
AUTH_DS = "logs-auth.demo-default"
APP_DS = "logs-app.demo-default"
TEMPLATE = "demo-bank-ato"
RANDOM_SEED = 4217

VICTIM = ("m.kovac", "BR-SOF-01", "WS-SOF-0142")
OTHER_USERS = [
    ("i.petrov", "BR-SOF-01", "WS-SOF-0107"),
    ("d.georgieva", "BR-SOF-01", "WS-SOF-0119"),
    ("n.ivanov", "BR-SOF-02", "WS-SOF-0203"),
    ("e.dimitrova", "BR-SOF-02", "WS-SOF-0211"),
    ("k.stoyanov", "BR-PLV-01", "WS-PLV-0104"),
    ("a.todorova", "BR-PLV-01", "WS-PLV-0112"),
    ("v.nikolov", "BR-VAR-01", "WS-VAR-0101"),
    ("s.angelova", "BR-VAR-01", "WS-VAR-0109"),
    ("p.hristov", "BR-BUR-01", "WS-BUR-0102"),
    ("r.koleva", "BR-BUR-01", "WS-BUR-0106"),
    ("t.marinov", "BR-SOF-03", "WS-SOF-0305"),
    ("g.popova", "BR-SOF-03", "WS-SOF-0314"),
]
BRANCHES = sorted({b for _, b, _ in OTHER_USERS} | {VICTIM[1]})

# Documentation-range IPs (RFC 5737) so nothing resolves to a real network.
OFFICE = {
    "ip": "203.0.113.24",
    "geo": {"country_iso_code": "BG", "country_name": "Bulgaria", "city_name": "Sofia",
            "location": {"lat": 42.6977, "lon": 23.3219}},
}
FOREIGN = {
    "ip": "198.51.100.77",
    "geo": {"country_iso_code": "BR", "country_name": "Brazil", "city_name": "Sao Paulo",
            "location": {"lat": -23.5505, "lon": -46.6333}},
}
UA_OFFICE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"
UA_FOREIGN = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

RULE_IDS = {
    "travel": "demo-bank-ato-impossible-travel",
    "bulk": "demo-bank-ato-bulk-customer-access",
    "newcountry": "demo-bank-ato-new-login-country",
}


# --------------------------------------------------------------------------- HTTP

class Client:
    def __init__(self, es_url, kb_url, api_key, space, ca_cert=None, insecure=False):
        self.es_url = es_url.rstrip("/")
        self.kb_url = kb_url.rstrip("/")
        self.api_key = api_key
        self.space = space
        self.space_prefix = "" if space == "default" else f"/s/{space}"
        if insecure:
            self.ctx = ssl._create_unverified_context()
        elif ca_cert:
            self.ctx = ssl.create_default_context(cafile=ca_cert)
        else:
            self.ctx = ssl.create_default_context()

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


def auth_event(ts, user, branch, *, action, outcome, loc, host, ua, device, method, message):
    return {
        "@timestamp": iso(ts),
        "message": message,
        "event": {"kind": "event", "category": "authentication", "type": "start",
                  "action": action, "outcome": outcome, "dataset": "auth.demo",
                  "module": "northbridge_sso"},
        "user": {"name": user},
        "source": {"ip": loc["ip"], "geo": loc["geo"]},
        "host": {"name": host},
        "service": {"name": "northbridge-sso"},
        "user_agent": {"original": ua},
        "northbridge": {"branch": branch, "device_id": device, "auth_method": method},
        "labels": {"demo": DEMO_TAG},
    }


def app_event(ts, user, user_branch, *, action, service, host, loc, records, branch, message):
    return {
        "@timestamp": iso(ts),
        "message": message,
        "event": {"kind": "event", "category": "database", "type": "access",
                  "action": action, "outcome": "success", "dataset": "app.demo",
                  "module": "northbridge_apps"},
        "user": {"name": user},
        "source": {"ip": loc["ip"], "geo": loc["geo"]},
        "host": {"name": host},
        "service": {"name": service},
        "northbridge": {"record_count": records, "branch": branch, "user_branch": user_branch},
        "labels": {"demo": DEMO_TAG},
    }


SERVICES = {"crm-prod": "crm-prod-01", "custdb-prod": "custdb-prod-01"}


def normal_day(docs, rng, login, user, branch, ws, reads):
    docs.append((AUTH_DS, auth_event(
        login, user, branch, action="sso_login", outcome="success", loc=OFFICE, host="sso-idp-01",
        ua=UA_OFFICE, device=f"dev-{ws.lower()}", method="password+mfa_push",
        message=f"SSO login succeeded for {user} from {OFFICE['geo']['city_name']}")))
    t = login
    for _ in range(reads):
        t += timedelta(minutes=rng.randint(10, 50))
        svc = rng.choice(list(SERVICES))
        n = rng.randint(3, 6)
        docs.append((APP_DS, app_event(
            t, user, branch, action="customer_record_read", service=svc, host=SERVICES[svc],
            loc=OFFICE, records=n, branch=branch,
            message=f"{user} read {n} customer records ({branch}) via {svc}")))


def build_events(now, rng):
    docs = []
    users = [VICTIM] + OTHER_USERS

    # Baseline: previous 14 days, weekdays, 08:00-09:30 Sofia (06:00-07:30 UTC) logins.
    for days_ago in range(14, 0, -1):
        day = (now - timedelta(days=days_ago)).replace(hour=0, minute=0, second=0, microsecond=0)
        if day.weekday() >= 5:
            continue
        for user, branch, ws in users:
            login = day + timedelta(hours=6, minutes=rng.randint(0, 90))
            normal_day(docs, rng, login, user, branch, ws, reads=rng.randint(5, 8))

    # Today: normal activity for everyone else, inside the rules' 2h lookback.
    for user, branch, ws in OTHER_USERS:
        login = now - timedelta(minutes=rng.randint(55, 110))
        normal_day(docs, rng, login, user, branch, ws, reads=rng.randint(1, 3))

    # Today: the victim's legitimate office session.
    user, branch, ws = VICTIM
    docs.append((AUTH_DS, auth_event(
        now - timedelta(minutes=50), user, branch, action="sso_login", outcome="success",
        loc=OFFICE, host="sso-idp-01", ua=UA_OFFICE, device=f"dev-{ws.lower()}",
        method="password+mfa_push",
        message=f"SSO login succeeded for {user} from Sofia")))
    for m in (47, 43, 39):
        docs.append((APP_DS, app_event(
            now - timedelta(minutes=m), user, branch, action="customer_record_read",
            service="crm-prod", host=SERVICES["crm-prod"], loc=OFFICE, records=rng.randint(3, 5),
            branch=branch, message=f"{user} read customer records ({branch}) via crm-prod")))

    # Attack: MFA fatigue from Sao Paulo, then success on a new device.
    for m in (34, 33, 32, 31):
        docs.append((AUTH_DS, auth_event(
            now - timedelta(minutes=m), user, branch, action="mfa_push", outcome="failure",
            loc=FOREIGN, host="vpn-gw-01", ua=UA_FOREIGN, device="dev-unknown-7f3a",
            method="password+mfa_push",
            message=f"MFA push denied for {user} (request from Sao Paulo)")))
    docs.append((AUTH_DS, auth_event(
        now - timedelta(minutes=30), user, branch, action="sso_login", outcome="success",
        loc=FOREIGN, host="vpn-gw-01", ua=UA_FOREIGN, device="dev-unknown-7f3a",
        method="password+mfa_push",
        message=f"SSO login succeeded for {user} from Sao Paulo on unrecognised device")))

    # Attack: bulk reads across other branches, then an export.
    other_branches = [b for b in BRANCHES if b != branch]
    for m in range(25, 7, -1):
        b = rng.choice(other_branches)
        n = rng.randint(50, 90)
        docs.append((APP_DS, app_event(
            now - timedelta(minutes=m, seconds=rng.randint(0, 50)), user, branch,
            action="customer_record_read", service="custdb-prod", host=SERVICES["custdb-prod"],
            loc=FOREIGN, records=n, branch=b,
            message=f"{user} read {n} customer records ({b}) via custdb-prod")))
    docs.append((APP_DS, app_event(
        now - timedelta(minutes=6), user, branch, action="customer_record_export",
        service="custdb-prod", host=SERVICES["custdb-prod"], loc=FOREIGN, records=1450,
        branch="ALL", message=f"{user} exported 1450 customer records to CSV via custdb-prod")))

    return docs


# --------------------------------------------------------------------------- template

KW = {"type": "keyword"}
TEMPLATE_BODY = {
    "index_patterns": ["logs-auth.demo-*", "logs-app.demo-*"],
    "data_stream": {},
    "priority": 500,
    "_meta": {"description": "Northbridge Bank ATO demo data", "demo": DEMO_TAG},
    "template": {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "message": {"type": "text"},
                "event": {"properties": {k: KW for k in
                                         ("kind", "category", "type", "action", "outcome",
                                          "dataset", "module")}},
                "user": {"properties": {"name": KW}},
                "host": {"properties": {"name": KW}},
                "service": {"properties": {"name": KW}},
                "user_agent": {"properties": {"original": KW}},
                "source": {"properties": {
                    "ip": {"type": "ip"},
                    "geo": {"properties": {
                        "country_iso_code": KW, "country_name": KW, "city_name": KW,
                        "location": {"type": "geo_point"}}}}},
                "northbridge": {"properties": {
                    "record_count": {"type": "long"}, "branch": KW, "user_branch": KW,
                    "device_id": KW, "auth_method": KW}},
                "labels": {"properties": {"demo": KW}},
            }
        }
    },
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


COMMON = {"enabled": True, "interval": "5m", "from": "now-2h", "max_signals": 100,
          "tags": ["demo:bank-ato", "Identity", "Northbridge Bank"]}
SUPPRESS_BY_USER = {"group_by": ["user.name"], "duration": {"value": 4, "unit": "h"},
                    "missing_fields_strategy": "suppress"}

RULES = [
    {**COMMON,
     "rule_id": RULE_IDS["travel"],
     "name": "Impossible travel: successful logins from multiple countries",
     "description": "A user authenticated successfully from more than one country within "
                    "the lookback window, which is not physically possible.",
     "type": "esql", "language": "esql",
     "query": (
         "FROM logs-auth.demo-*\n"
         "| WHERE event.category == \"authentication\" AND event.outcome == \"success\"\n"
         "| STATS countries = COUNT_DISTINCT(source.geo.country_iso_code),\n"
         "        country_list = VALUES(source.geo.country_iso_code),\n"
         "        source_ips = VALUES(source.ip),\n"
         "        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY user.name\n"
         "| WHERE countries > 1"),
     "severity": "high", "risk_score": 73,
     "threat": mitre("TA0001", "Initial Access", "T1078", "Valid Accounts"),
     "alert_suppression": SUPPRESS_BY_USER},
    {**COMMON,
     "rule_id": RULE_IDS["bulk"],
     "name": "Bulk customer data access by a single user",
     "description": "A user read or exported an unusually large number of customer records "
                    "within the lookback window.",
     "type": "esql", "language": "esql",
     "query": (
         "FROM logs-app.demo-*\n"
         "| WHERE event.action IN (\"customer_record_read\", \"customer_record_export\")\n"
         "| STATS records = SUM(northbridge.record_count),\n"
         "        branches = COUNT_DISTINCT(northbridge.branch),\n"
         "        services = VALUES(service.name) BY user.name\n"
         "| WHERE records > 500"),
     "severity": "critical", "risk_score": 91,
     "threat": mitre("TA0009", "Collection", "T1213", "Data from Information Repositories"),
     "alert_suppression": SUPPRESS_BY_USER},
    {**COMMON,
     "rule_id": RULE_IDS["newcountry"],
     "name": "First successful login from a new country for user",
     "description": "A user logged in successfully from a country not seen for them in the "
                    "previous 14 days.",
     "type": "new_terms", "language": "kuery",
     "index": ["logs-auth.demo-*"],
     "query": "event.category:authentication and event.outcome:success",
     "new_terms_fields": ["user.name", "source.geo.country_iso_code"],
     "history_window_start": "now-14d",
     "severity": "medium", "risk_score": 47,
     "threat": mitre("TA0001", "Initial Access", "T1078", "Valid Accounts")},
]


def rule_path(rule_id):
    return "/api/detection_engine/rules?rule_id=" + urllib.parse.quote(rule_id)


def upsert_rules(c):
    for rule in RULES:
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


def bulk_index(c, docs, batch=1000):
    for i in range(0, len(docs), batch):
        lines = []
        for index, doc in docs[i:i + batch]:
            lines.append(json.dumps({"create": {"_index": index}}))
            lines.append(json.dumps(doc))
        st, body = c.es("POST", "/_bulk?refresh=wait_for", "\n".join(lines) + "\n", ndjson=True)
        if st >= 300:
            fail(f"bulk request failed (HTTP {st})", body)
        if body.get("errors"):
            errs = [it["create"]["error"] for it in body["items"] if "error" in it.get("create", {})]
            fail(f"{len(errs)} documents rejected in batch starting at {i}", errs[:3])


def delete_data(c):
    for ds in (AUTH_DS, APP_DS):
        st, body = c.es("DELETE", f"/_data_stream/{ds}")
        if st not in (200, 404):
            fail(f"deleting data stream {ds} failed (HTTP {st})", body)


def seed(c, with_rules, wait_minutes):
    st, me = c.es("GET", "/_security/_authenticate")
    if st >= 300:
        fail("API key rejected by Elasticsearch", me)
    print(f"Authenticated as {me.get('username')} "
          f"(api key: {me.get('api_key', {}).get('name', 'n/a')})")

    now = datetime.now(timezone.utc)
    docs = build_events(now, random.Random(RANDOM_SEED))

    print("Removing previous demo data streams (alerts are kept; use --reset for those)")
    delete_data(c)

    st, body = c.es("PUT", f"/_index_template/{TEMPLATE}", TEMPLATE_BODY)
    if st >= 300:
        fail("creating index template failed", body)
    print(f"  + template {TEMPLATE}")

    bulk_index(c, docs)
    n_auth = sum(1 for i, _ in docs if i == AUTH_DS)
    print(f"  + {n_auth} events -> {AUTH_DS}")
    print(f"  + {len(docs) - n_auth} events -> {APP_DS}")

    if with_rules:
        upsert_rules(c)
        if wait_minutes:
            wait_for_alerts(c, wait_minutes)
    print(f"Done. Attack window: {iso(now - timedelta(minutes=34))} .. {iso(now - timedelta(minutes=6))}")


def wait_for_alerts(c, minutes):
    expected = {r["rule_id"] for r in RULES}
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
        seen = {h["_source"].get("kibana.alert.rule.rule_id") or
                h["_source"].get("kibana", {}).get("alert", {}).get("rule", {}).get("rule_id")
                for h in hits}
        if expected <= seen:
            break
        time.sleep(30)
    if not hits:
        print("  ! no alerts yet. Check the rules' execution status in Security > Rules.")
        return
    for h in hits:
        s = h["_source"]
        flat = lambda k: s.get(k) or _dig(s, k)
        print(f"  * {flat('kibana.alert.severity'):8} {flat('user.name') or '-':12} "
              f"{flat('kibana.alert.rule.name')}  uuid={flat('kibana.alert.uuid')}")


def _dig(d, dotted):
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
    print(f"  - data streams {AUTH_DS}, {APP_DS}")
    st, _ = c.es("DELETE", f"/_index_template/{TEMPLATE}")
    print(f"  - template {TEMPLATE}: {'deleted' if st == 200 else 'not found'}")
    print("Reset done. Close or delete any demo Kibana cases and Mattermost posts by hand.")


def dry_run():
    now = datetime.now(timezone.utc)
    docs = build_events(now, random.Random(RANDOM_SEED))
    n_auth = sum(1 for i, _ in docs if i == AUTH_DS)
    print(f"{n_auth} auth events, {len(docs) - n_auth} app events")
    window = now - timedelta(hours=2)
    in_window = [d for _, d in docs if d["@timestamp"] >= iso(window)]
    by_user = {}
    for d in in_window:
        u = by_user.setdefault(d["user"]["name"], {"countries": set(), "records": 0})
        if d["event"]["category"] == "authentication" and d["event"]["outcome"] == "success":
            u["countries"].add(d["source"]["geo"]["country_iso_code"])
        u["records"] += d.get("northbridge", {}).get("record_count", 0)
    print("Last 2h (what the ES|QL rules will see):")
    for name, u in sorted(by_user.items()):
        flag = []
        if len(u["countries"]) > 1:
            flag.append("IMPOSSIBLE-TRAVEL")
        if u["records"] > 500:
            flag.append("BULK-ACCESS")
        print(f"  {name:12} countries={sorted(u['countries'])} records={u['records']:5} {' '.join(flag)}")
    print("Sample attack event:")
    print(json.dumps(next(d for _, d in docs if d["source"]["ip"] == FOREIGN["ip"]), indent=2))


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
    ap.add_argument("--no-rules", action="store_true", help="seed events only")
    ap.add_argument("--wait-alerts", type=int, metavar="MIN", default=0,
                    help="after seeding, poll up to MIN minutes for the demo alerts")
    ap.add_argument("--dry-run", action="store_true", help="generate locally and summarise; no network")
    args = ap.parse_args()
    load_dotenv()

    if args.dry_run:
        dry_run()
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
        seed(c, with_rules=not args.no_rules, wait_minutes=args.wait_alerts)


if __name__ == "__main__":
    main()