import json
import subprocess
from pathlib import Path

from conftest import EXAMPLES

from iamlens.check import RULES, check_document, render_markdown, render_sarif, run_check
from iamlens.cli import main

GOOD = EXAMPLES / "policies"
BAD = EXAMPLES / "policies-bad"


def rules_for(doc, org=frozenset()):
    return sorted({f.rule for f in check_document(doc, "x.json", json.dumps(doc, indent=2), set(org))})


def test_static_rules_each_fire():
    v = "2012-10-17"
    assert rules_for({"Version": v, "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}) == ["IAM001"]
    assert "IAM002" in rules_for(
        {"Version": v, "Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}
    )
    assert rules_for(
        {
            "Version": v,
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}
            ],
        }
    ) == ["IAM003"]
    assert rules_for(
        {
            "Version": v,
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "444455556666"}, "Action": "sts:AssumeRole"}],
        }
    ) == ["IAM004"]
    assert rules_for({"Version": v, "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}) == [
        "IAM005"
    ]
    assert rules_for({"Version": v, "Statement": [{"Effect": "Allow", "Action": "sqs:*", "Resource": "*"}]}) == [
        "IAM006"
    ]
    assert rules_for({"Version": v, "Statement": [{"Effect": "Allow"}]}) == ["IAM007"]
    assert rules_for(
        {
            "Version": "2008-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}],
        }
    ) == ["IAM008"]


def test_static_rules_do_not_fire_on_safe_policies():
    v = "2012-10-17"
    trust = {
        "Version": v,
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "444455556666"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": "x"}},
            }
        ],
    }
    assert rules_for(trust) == []
    org_trust = {
        "Version": v,
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "111100013333"}, "Action": "sts:AssumeRole"}],
    }
    assert rules_for(org_trust, {"111100013333"}) == []
    scoped = {
        "Version": v,
        "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::1:role/app-*"}],
    }
    assert rules_for(scoped) == []


def test_examples_gate():
    good, _ = run_check(GOOD)
    bad, files = run_check(BAD)
    assert all(f.severity in ("medium", "low") for f in good)
    assert {f.rule for f in bad} >= {"IAM001", "IAM002", "IAM003", "IAM004", "IAM005", "IAM007"}
    assert len(files) == 8


def test_line_numbers_point_at_the_statement():
    bad, _ = run_check(BAD)
    f = next(x for x in bad if x.rule == "IAM005" and "PassRole" in x.message)
    lines = Path(f.file).read_text().splitlines()
    assert '"Effect"' in lines[f.line - 1]


def test_sarif_shape():
    bad, _ = run_check(BAD)
    sarif = json.loads(render_sarif(bad))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "iamlens"
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert rule_ids == list(RULES)
    for r in run["tool"]["driver"]["rules"]:
        assert float(r["properties"]["security-severity"]) > 0
    for res in run["results"]:
        assert rule_ids[res["ruleIndex"]] == res["ruleId"]
        assert res["level"] in ("error", "warning", "note")
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"].endswith(".json") and loc["region"]["startLine"] >= 1
        assert res["partialFingerprints"]["iamlens/v1"]


def test_markdown_summary():
    bad, files = run_check(BAD)
    md = render_markdown(bad, files, "high", True)
    assert md.startswith("## iamlens policy check") and "**FAILED**" in md
    assert "| Severity | Rule | File | Line | Message |" in md


def test_cli_check_exit_codes_and_outputs(tmp_path, monkeypatch, capsys):
    step = tmp_path / "step.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step))
    sarif = tmp_path / "out.sarif"
    assert main(["check", str(GOOD), "--sarif", str(sarif), "--quiet"]) == 0
    assert main(["check", str(BAD), "--sarif", str(sarif), "--quiet"]) == 1
    assert json.loads(sarif.read_text())["runs"][0]["results"]
    assert step.read_text().count("## iamlens policy check") == 2
    assert main(["check", str(BAD), "--fail-on", "critical", "--quiet"]) == 1
    assert main(["check", str(GOOD), "--fail-on", "medium", "--quiet"]) == 1
    assert main(["check", str(tmp_path / "missing")]) == 2


def test_cli_check_only_changed_files(tmp_path):
    changed = BAD / "orders-api-role.json"  # a clean file inside the bad folder
    assert main(["check", str(BAD), "--changed", str(changed), "--quiet"]) == 0
    assert main(["check", str(BAD), "--changed", str(BAD / "platform-admin.json"), "--quiet"]) == 1


def test_cli_check_git_base(tmp_path):
    repo = tmp_path / "repo"
    pol = repo / "policies"
    pol.mkdir(parents=True)

    def git(*a):
        subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false", *a], check=True, capture_output=True)

    git("init", "-q")
    git("symbolic-ref", "HEAD", "refs/heads/main")
    git("config", "user.email", "ci@example.com")
    git("config", "user.name", "ci")
    (pol / "old-admin.json").write_text((BAD / "platform-admin.json").read_text())
    git("add", ".")
    git("commit", "-qm", "base")
    git("checkout", "-qb", "feature")
    (pol / "new.json").write_text((GOOD / "orders-api-role.json").read_text())
    git("add", ".")
    git("commit", "-qm", "change")
    # Only new.json changed since main, so the old admin policy does not fail this change.
    assert main(["check", str(pol), "--base", "main", "--quiet"]) == 0
    (pol / "new.json").write_text((BAD / "power-user.json").read_text())
    git("commit", "-qam", "worse")
    assert main(["check", str(pol), "--base", "main", "--quiet"]) == 1


def test_cli_simulate_and_suggest(capsys):
    assert (
        main(
            [
                "simulate",
                "111100143333:role/app-ml-worker",
                "s3:GetObject",
                "arn:aws:s3:::cobaltline-data-lake/curated/features-2026.parquet",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert out.startswith("Allow") and "resource policy" in out
    assert main(["simulate", "vendor-quillsearch-indexer", "iam:CreateUser", "*", "--json"]) == 3
    assert main(["suggest", "vendor-parcelwise-monitoring"]) == 0
    assert "PASS" in capsys.readouterr().out


def test_generator_is_deterministic():
    from iamlens.generator import build

    a, ea = build(7)
    b, eb = build(7)
    assert a == b and ea[:200] == eb[:200]
    assert len(a["accounts"]) == 40 and 280 <= len(a["principals"]) <= 330
    assert {"111122223333"} <= {x["id"] for x in a["accounts"]}
