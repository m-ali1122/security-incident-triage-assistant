import pytest

from triage.graph.cluster import cluster, renumber
from triage.graph.resolve import get_graph
from triage.models import Cite, Finding, Incident


@pytest.fixture(scope="module")
def g():
    return get_graph()


def test_pool_ip_inside_session(g):
    c = g.resolve("10.10.3.45", "2026-11-04T06:10:00Z")
    assert c.user.username == "amalik"
    assert c.session.session_id == "VS-20433"
    assert c.steps[1].cite.file == "11_vpn_auth_log.md" and c.steps[1].cite.line == 7
    assert "session VS-20433 (11_vpn_auth_log.md line 7)" in c.text
    assert all(l.basis in ("direct", "inferred") for l in c.links)


def test_pool_ip_outside_session(g):
    c = g.resolve("ip:10.10.3.45", "2026-11-04T09:00:00Z")
    assert c.user is None and "no VPN session" in c.note


def test_pool_ip_no_time_single_user(g):
    c = g.resolve("10.10.3.45")
    assert c.user.username == "amalik" and "session windows" in c.note


def test_pool_ip_reused(g):
    assert g.resolve("10.10.3.18", "2026-11-04T17:40:00Z").session.session_id == "VS-20502"
    assert g.resolve("10.10.3.18", "2026-11-04T17:40:00Z").user.username == "braza"
    assert g.resolve("10.10.3.18", "2026-11-04T14:00:00Z").user is None
    assert g.user_for_ip("10.10.3.18", "2026-11-04T14:00:00Z") is None


def test_fqdn_and_short_names(g):
    assert g.resolve("FS01.orbit.local").asset.tag == "A-1005"
    assert g.resolve("FS01").asset.tag == "A-1005"
    assert g.resolve("SRV-FS01").asset.tag == "A-1005"
    assert g.resolve("DC01").asset.hostname == "SRV-DC01"


def test_public_ip(g):
    assert g.resolve("203.0.113.10").asset.hostname == "SRV-WEB01"
    assert g.asset_for_ip("203.0.113.10").tag == "A-1010"


def test_laptop_ip_before_lease(g):
    c = g.resolve("10.20.5.22", "2026-11-04T03:55:00Z")
    assert c.asset.hostname == "LT-FIN-022" and c.user.username == "sraheel"
    assert c.steps[1].cite.row == "A-2022"


def test_user_identifiers(g):
    for ident in (r"ORBIT\amalik", "Ayesha Malik", "amalik@orbitlogistics.example",
                  "user:amalik", "+92-300-5550114"):
        assert g.resolve(ident).user.username == "amalik", ident
    assert g.resolve("amalik").asset.tag == "A-2014"
    assert g.resolve("VS-20433").user.username == "amalik"


def test_external_ip_and_domain(g):
    c = g.resolve("198.51.100.77")
    assert c.kind == "ext_ip" and c.is_external and c.node == "ext_ip:198.51.100.77"
    assert any(l.type == "hosts_domain" and l.b == "domain:orbit-payroll-verify.example" for l in c.links)
    assert g.resolve("orbit-payroll-verify.example").kind == "domain"


def test_touched_and_events_for(g):
    evs = g.touched("amalik", "2026-11-04T06:15:00Z", "2026-11-04T06:30:00Z")
    assert any(e.fields.get("dst_port") == 445 for e in evs)
    assert {e.event_id for e in g.touched("SRV-FS01")}
    e = next(e for e in g.events if e.kind == "firewall_session")
    r = g.events_for(e)
    assert set(r) == {"src", "dst"}
    j = g.to_json()
    assert j["nodes"] and j["edges"]


def F(fid, rule, entities, label="suspected"):
    return Finding(finding_id=fid, rule=rule, cites_rule="1.1", label=label, statement="s",
                   assumption="a", evidence=[Cite("f.md", line=1)], entities=entities)


def test_shared_actor_joins():
    inc = cluster([F("F1", "r", ["actor:ext_ip:1.2.3.4", "asset:A-1"]),
                   F("F2", "r", ["actor:ext_ip:1.2.3.4", "actor:session:VS-1"]),
                   F("F3", "r", ["actor:session:VS-1"])])
    assert len(inc) == 1 and inc[0].incident_id == "INC-1" and len(inc[0].findings) == 3


def test_shared_target_does_not_join():
    inc = cluster([F("F1", "r", ["actor:ext_ip:1.2.3.4", "asset:A-1", "user:x"]),
                   F("F2", "r", ["actor:ext_ip:9.9.9.9", "asset:A-1", "user:x"])])
    assert len(inc) == 2


def test_harmless_and_no_actor_excluded():
    inc = cluster([F("F1", "r", ["actor:ext_ip:1.2.3.4"], label="harmless"),
                   F("F2", "r", ["asset:A-1"]),
                   F("F3", "r", ["actor:ext_ip:1.2.3.4"])])
    assert len(inc) == 1 and [f.finding_id for f in inc[0].findings] == ["F3"]


def test_concurrent_use_is_anomaly_and_order():
    inc = cluster([F("F1", "concurrent_use", ["actor:session:VS-9"]),
                   F("F2", "x", ["actor:ext_ip:1.1.1.1"]),
                   F("F3", "x", ["actor:ext_ip:1.1.1.1"])])
    ids = [i.incident_id for i in inc]
    assert ids == ["INC-1", "ANOM-1"]
    assert inc[1].findings[0].rule == "concurrent_use"


def test_renumber_by_severity():
    a, b = Incident("INC-1", severity="P2"), Incident("INC-2", severity="P1")
    assert [i.incident_id for i in renumber([a, b])] == ["INC-1", "INC-2"]
    assert renumber([a, b])[0] is b
