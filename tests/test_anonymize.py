from triage.answer.anonymize import Anonymizer

KNOWN = {
    "user": ["amalik", "sraza"],
    "name": ["Ayesha Malik", "Sana Raza"],
    "email": ["amalik@orbitlogistics.example"],
    "phone": ["+92-300-5550114"],
    "ip": ["10.10.3.45"],
    "host": ["SRV-FS01", "LT-FIN-014"],
}


def make():
    return Anonymizer(KNOWN)


def test_basic_tokens_and_roundtrip():
    a = make()
    text = "Ayesha Malik (amalik) on LT-FIN-014 at 10.10.3.45 reached SRV-FS01."
    out = a.anonymize(text)
    assert "amalik" not in out and "10.10.3.45" not in out and "SRV-FS01" not in out
    for tok in ("NAME_1", "USER_1", "HOST_1", "IP_1", "HOST_2"):
        assert tok in out
    assert a.deanonymize(out) == text


def test_stable_tokens():
    a = make()
    assert a.anonymize("amalik") == a.anonymize("amalik") == "USER_1"
    assert a.anonymize("AMALIK") == "USER_1"
    assert a.anonymize("sraza") == "USER_2"


def test_longest_first_email_not_half_replaced():
    a = make()
    out = a.anonymize("mail amalik@orbitlogistics.example from amalik")
    assert out == "mail EMAIL_1 from USER_1"
    assert a.deanonymize(out) == "mail amalik@orbitlogistics.example from amalik"


def test_regex_detection_without_known():
    a = Anonymizer()
    out = a.anonymize("from 203.0.113.9 to 10.0.0.1 mail bob@corp.example call +92-300-5550114 again 203.0.113.9")
    assert out == "from IP_1 to IP_2 mail EMAIL_1 call PHONE_1 again IP_1"


def test_word_boundary_and_case():
    a = make()
    assert a.anonymize("amaliks and xamalik") == "amaliks and xamalik"
    assert a.anonymize("ayesha malik") == "NAME_1"


def test_non_pii_ids_untouched():
    a = make()
    s = "VS-20433 ALT-9002 CHG-2026-1104-02 RB-CRED-02 A-1005 11_vpn_auth_log.md line 7 at 2026-11-04T06:03:12Z"
    assert a.anonymize(s) == s


def test_walks_structures():
    a = make()
    obj = {"u": ["amalik", {"ip": "10.10.3.45"}], "n": 5, "k": None}
    out = a.anonymize(obj)
    assert out == {"u": ["USER_1", {"ip": "IP_1"}], "n": 5, "k": None}
    assert a.deanonymize(out) == obj


def test_bad_ip_not_matched():
    a = Anonymizer()
    assert a.anonymize("version 999.1.1.1") == "version 999.1.1.1"


def test_unmapped_tokens():
    a = make()
    a.anonymize("amalik")
    assert a.unmapped_tokens("USER_1 and USER_7 and IP_3") == ["USER_7", "IP_3"]
    assert a.unmapped_tokens("nothing here") == []


def test_deanonymize_token_prefix_safe():
    a = Anonymizer({"ip": [f"10.0.0.{i}" for i in range(1, 12)]})
    for i in range(1, 12):
        a.anonymize(f"10.0.0.{i}")
    assert a.deanonymize("IP_11 IP_1") == "10.0.0.11 10.0.0.1"
