import pytest
from conftest import EXAMPLES
from fastapi.testclient import TestClient

from iamlens.app import create_app


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    app = create_app(EXAMPLES, tmp_path_factory.mktemp("state"))
    with TestClient(app) as c:
        yield c


def test_health_and_metrics(client):
    h = client.get("/healthz").json()
    assert h["status"] == "ok" and h["principals"] > 280 and h["accounts"] == 40
    m = client.get("/metrics").text
    assert "iamlens_findings_critical" in m and "iamlens_http_request_duration_seconds_bucket" in m
    assert client.get("/healthz").headers["x-request-id"]


def test_index_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "<title>IAM Lens</title>" in r.text


def test_summary_and_findings(client):
    s = client.get("/api/summary").json()
    assert sum(s["by_severity"].values()) == s["findings"]
    r = client.get("/api/findings", params={"severity": "critical", "limit": 500}).json()
    assert r["total"] == s["by_severity"]["critical"]
    assert all(f["severity"] == "critical" for f in r["items"])
    one = r["items"][0]
    assert client.get(f"/api/findings/{one['id']}").json()["subject"] == one["subject"]
    assert client.get("/api/findings/F-nope").status_code == 404
    t = client.get("/api/findings", params={"type": "public_resource_policy"}).json()
    assert t["total"] == 3


def test_principal_detail(client):
    items = client.get("/api/principals", params={"q": "app-ml-worker"}).json()["items"]
    arn = items[0]["arn"]
    d = client.get("/api/principal", params={"arn": arn}).json()
    assert d["arn"] == arn and d["usage"]["granted"] >= d["usage"]["used"]
    assert d["scps"] and d["policies"]
    assert client.get("/api/principal", params={"arn": "arn:aws:iam::1:user/ghost"}).status_code == 404


def test_simulate_endpoint(client):
    items = client.get("/api/principals", params={"q": "sandbox-admin"}).json()["items"]
    arn = items[0]["arn"]
    acct = arn.split(":")[4]
    d = client.post(
        "/api/simulate", json={"principal": arn, "action": "iam:CreateRole", "resource": f"arn:aws:iam::{acct}:role/x"}
    ).json()
    assert d["decision"] == "ImplicitDeny" and "SCP" in d["reason"]
    assert [s["stage"] for s in d["path"]][:2] == ["explicit deny", "service control policies"]
    ok = client.post(
        "/api/simulate",
        json={"principal": arn, "action": "s3:PutObject", "resource": "arn:aws:s3:::cobaltline-sandbox-1/tmp/x"},
    ).json()
    assert ok["allowed"]
    assert client.post("/api/simulate", json={"principal": arn}).status_code == 422
    assert client.post("/api/simulate", json={"principal": "nope", "action": "a", "resource": "*"}).status_code == 404


def test_least_privilege_endpoint(client):
    arn = client.get("/api/principals", params={"q": "vendor-parcelwise"}).json()["items"][0]["arn"]
    r = client.get("/api/least-privilege", params={"arn": arn}).json()
    assert r["proof"]["passed"] and r["granted_after"] < r["granted_before"]
    assert any(line.startswith("+") for line in r["diff"])
    s = client.get("/api/least-privilege/summary").json()
    assert s["reduction_pct"] > 50 and "rows" not in s


def test_escalation_endpoint(client):
    g = client.get("/api/escalation").json()
    ids = {n["id"] for n in g["nodes"]}
    assert "ADMIN" in ids
    assert all(e["from"] in ids and e["to"] in ids for e in g["edges"])
    assert sum(p["members"] for p in g["paths"]) == client.get("/api/summary").json()["escalation_paths"]


def test_campaign_end_to_end(client):
    c = client.post("/api/campaigns", json={"name": "Q4", "deadline": "2026-11-21"})
    assert c.status_code == 201
    cid = c.json()["id"]
    detail = client.get(f"/api/campaigns/{cid}", params={"status": "pending"}).json()
    item = detail["item_list"][0]
    bad = client.post(
        f"/api/campaigns/{cid}/items/{item['id']}/decision",
        json={"reviewer": "arn:aws:iam::1:user/intruder", "decision": "keep"},
    )
    assert bad.status_code == 403
    ok = client.post(
        f"/api/campaigns/{cid}/items/{item['id']}/decision",
        json={"reviewer": item["reviewer"], "decision": item["suggestion"]},
    )
    assert ok.status_code == 200 and ok.json()["decided_by"] == item["reviewer"]
    again = client.post(
        f"/api/campaigns/{cid}/items/{item['id']}/decision",
        json={"reviewer": item["reviewer"], "decision": item["suggestion"]},
    )
    assert again.status_code == 409
    esc = client.post(f"/api/campaigns/{cid}/escalate", json={"now": "2026-11-25"}).json()
    assert esc["escalated"] > 0
    after = client.get(f"/api/campaigns/{cid}", params={"status": "escalated"}).json()
    assert len(after["item_list"]) == esc["escalated"] == after["escalated"]
    csv_text = client.get(f"/api/campaigns/{cid}/evidence", params={"format": "csv"}).text
    assert csv_text.startswith("item,user")
    js = client.get(f"/api/campaigns/{cid}/evidence").json()
    assert js["summary"]["decided"] == 1 and js["integrity"]["head"]
    assert client.get("/api/campaigns").json()[0]["id"] == cid
    assert client.post("/api/campaigns", json={"deadline": "2020-01-01"}).status_code == 422
