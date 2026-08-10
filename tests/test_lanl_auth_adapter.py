"""LANLAuthCollector icin testler -- ADR 0014'teki uc katmanli
siniflandirma mantiginin ve outcome normalizasyonunun dogrulanmasi."""

import gzip
from datetime import timedelta
from pathlib import Path

from sentinelpath.collector.infrastructure.lanl_auth_adapter import LANLAuthCollector
from sentinelpath.collector.infrastructure.lanl_flows_adapter import (
    LANL_VIRTUAL_EPOCH,
    build_flow_technique_index,
)
from sentinelpath.core.models import EventSource, NormalizedEvent


def _write_auth_gz(path: Path, lines: list[str]) -> None:
    with gzip.open(path, "wt") as f:
        f.write("\n".join(lines) + "\n")


def test_remote_interactive_maps_to_rdp_high_confidence(tmp_path: Path) -> None:
    auth_path = tmp_path / "auth.txt.gz"
    _write_auth_gz(
        auth_path,
        ["1,U1@DOM1,U1@DOM1,C1,C2,Kerberos,RemoteInteractive,LogOn,Success"],
    )

    events = LANLAuthCollector(str(auth_path)).collect()

    assert len(events) == 1
    assert events[0].mitre_technique_id == "T1021.001"
    assert events[0].raw_action == "remote_interactive_logon:rdp"


def test_network_logon_with_cross_reference_gets_specific_technique(tmp_path: Path) -> None:
    auth_path = tmp_path / "auth.txt.gz"
    _write_auth_gz(
        auth_path, ["1,U1@DOM1,U1@DOM1,C1,C2,NTLM,Network,LogOn,Success"]
    )
    flow_event = NormalizedEvent(
        event_id="f1", timestamp=LANL_VIRTUAL_EPOCH + timedelta(seconds=1),
        source=EventSource.NETWORK, source_host="C1", target_host="C2",
        user=None, raw_action="tcp_connect:smb_admin_shares",
        mitre_technique_id="T1021.002",
    )
    flow_index = build_flow_technique_index([flow_event])

    events = LANLAuthCollector(str(auth_path), flow_index=flow_index).collect()

    assert events[0].mitre_technique_id == "T1021.002"
    assert "cross_referenced" in events[0].raw_action


def test_network_logon_without_cross_reference_gets_generic_technique(tmp_path: Path) -> None:
    auth_path = tmp_path / "auth.txt.gz"
    _write_auth_gz(
        auth_path, ["1,U1@DOM1,U1@DOM1,C1,C2,NTLM,Network,LogOn,Success"]
    )

    events = LANLAuthCollector(str(auth_path)).collect()  # flow_index yok

    assert events[0].mitre_technique_id == "T1021"
    assert events[0].raw_action == "network_logon:unclassified"


def test_machine_account_is_filtered_out(tmp_path: Path) -> None:
    auth_path = tmp_path / "auth.txt.gz"
    _write_auth_gz(
        auth_path, ["1,C101$@DOM1,C101$@DOM1,C1,C2,NTLM,Network,LogOn,Success"]
    )

    events = LANLAuthCollector(str(auth_path)).collect()

    assert events == []


def test_service_logon_type_is_filtered_out(tmp_path: Path) -> None:
    auth_path = tmp_path / "auth.txt.gz"
    _write_auth_gz(
        auth_path, ["1,U1@DOM1,SYSTEM@C1,C1,C1,Negotiate,Service,LogOn,Success"]
    )

    events = LANLAuthCollector(str(auth_path)).collect()

    assert events == []


def test_interactive_logon_type_is_filtered_out(tmp_path: Path) -> None:
    auth_path = tmp_path / "auth.txt.gz"
    _write_auth_gz(
        auth_path, ["1,U1@DOM1,U1@DOM1,C1,C1,Negotiate,Interactive,LogOn,Success"]
    )

    events = LANLAuthCollector(str(auth_path)).collect()

    assert events == []


def test_logoff_orientation_is_ignored(tmp_path: Path) -> None:
    auth_path = tmp_path / "auth.txt.gz"
    _write_auth_gz(
        auth_path, ["1,U1@DOM1,U1@DOM1,C1,C2,NTLM,Network,LogOff,Success"]
    )

    events = LANLAuthCollector(str(auth_path)).collect()

    assert events == []


def test_self_authentication_network_type_is_ignored(tmp_path: Path) -> None:
    auth_path = tmp_path / "auth.txt.gz"
    _write_auth_gz(
        auth_path, ["1,U1@DOM1,U1@DOM1,C1,C1,NTLM,Network,LogOn,Success"]
    )

    events = LANLAuthCollector(str(auth_path)).collect()

    assert events == []


def test_outcome_success_is_normalized_to_lowercase(tmp_path: Path) -> None:
    auth_path = tmp_path / "auth.txt.gz"
    _write_auth_gz(
        auth_path,
        ["1,U1@DOM1,U1@DOM1,C1,C2,Kerberos,RemoteInteractive,LogOn,Success"],
    )

    events = LANLAuthCollector(str(auth_path)).collect()

    assert events[0].metadata["outcome"] == "success"


def test_outcome_fail_is_normalized_to_failure(tmp_path: Path) -> None:
    auth_path = tmp_path / "auth.txt.gz"
    _write_auth_gz(
        auth_path,
        ["1,U1@DOM1,U1@DOM1,C1,C2,Kerberos,RemoteInteractive,LogOn,Fail"],
    )

    events = LANLAuthCollector(str(auth_path)).collect()

    assert events[0].metadata["outcome"] == "failure"


def test_failed_event_is_still_produced_not_dropped(tmp_path: Path) -> None:
    """Basarisiz girisler Graph Builder tarafindan kenar OLUSTURMAZ
    (bkz. networkx_adapter.py, outcome=='success' kontrolu), ama
    Feature Extraction'in failed_auth_ratio'yu hesaplayabilmesi icin
    event listesinden ATILMAMALIDIR."""
    auth_path = tmp_path / "auth.txt.gz"
    _write_auth_gz(
        auth_path,
        ["1,U1@DOM1,U1@DOM1,C1,C2,Kerberos,RemoteInteractive,LogOn,Fail"],
    )

    events = LANLAuthCollector(str(auth_path)).collect()

    assert len(events) == 1


def test_source_name_reports_path(tmp_path: Path) -> None:
    auth_path = tmp_path / "auth.txt.gz"
    _write_auth_gz(
        auth_path,
        ["1,U1@DOM1,U1@DOM1,C1,C2,Kerberos,RemoteInteractive,LogOn,Success"],
    )

    collector = LANLAuthCollector(str(auth_path))

    assert str(auth_path) in collector.source_name()