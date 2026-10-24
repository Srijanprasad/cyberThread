import pytest
from fusion.fusion_engine import FusionEngine
from schemas.events import Alert, AlertEntities, AlertEvidence


def test_fusion_deduplication():
    engine = FusionEngine()
    alert1 = Alert(
        ts_start=100.0,
        ts_end=101.0,
        threat="syn_flood",
        confidence=0.85,
        entities=AlertEntities(dst_ips=["10.77.2.10"]),
    )
    alert2 = Alert(
        ts_start=102.0,
        ts_end=103.0,
        threat="syn_flood",
        confidence=0.89,
        entities=AlertEntities(dst_ips=["10.77.2.10"]),
    )

    p1 = engine.process_raw_alert(alert1)
    assert p1 is not None

    # Within dedupe window (10s), should be suppressed
    p2 = engine.process_raw_alert(alert2)
    assert p2 is None


def test_fusion_multi_vector_c2_correlation():
    engine = FusionEngine()
    client = "10.77.1.105"

    dga_alert = Alert(
        ts_start=100.0,
        ts_end=105.0,
        threat="dga",
        confidence=0.80,
        entities=AlertEntities(src_ips=[client], dst_ips=["10.77.2.53"]),
    )
    beacon_alert = Alert(
        ts_start=105.0,
        ts_end=120.0,
        threat="c2_beacon",
        confidence=0.88,
        entities=AlertEntities(src_ips=[client], dst_ips=["10.77.2.99"]),
    )

    engine.process_raw_alert(dga_alert)
    engine.process_raw_alert(beacon_alert)

    # Check that a correlated incident was created
    incidents = [a for a in engine.final_alerts if a.threat == "probable_c2_infection"]
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.severity == "CRITICAL"
    assert client in inc.entities.src_ips
