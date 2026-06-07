import csv
import importlib.util
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
ANALYZER_PATH = REPO_ROOT / "examples" / "analyze_escc_fca_logs.py"
spec = importlib.util.spec_from_file_location("analyze_escc_fca_logs", ANALYZER_PATH)
analyzer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(analyzer)


CAN_HEADER = ["unix_ns", "mono_s", "src", "bus", "returned", "rejected", "addr_hex", "name", "len", "data_hex"]
EVENTS_HEADER = ["unix_ns", "mono_s", "event", "src", "bus", "returned", "rejected", "addr_hex", "name", "data_hex", "details"]
HEALTH_HEADER = [
  "unix_ns",
  "mono_s",
  "bus2_total_error_cnt",
  "bus2_can_core_reset_count",
  "bus2_bus_off_cnt",
  "bus2_total_tx_lost_cnt",
  "bus2_total_rx_lost_cnt",
  "bus2_total_tx_checksum_error_cnt",
  "bus2_last_stored_error",
  "bus2_last_data_stored_error",
  "bus2_canfd_enabled",
  "bus2_brs_enabled",
]


def write_capture(tmp_path, can_rows, health_rows, event_rows=None):
  capture = tmp_path / "capture"
  capture.mkdir()
  with (capture / "can.csv").open("w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(CAN_HEADER)
    writer.writerows(can_rows)
  if event_rows is not None:
    with (capture / "events.csv").open("w", newline="") as f:
      writer = csv.writer(f)
      writer.writerow(EVENTS_HEADER)
      writer.writerows(event_rows)
  with (capture / "health.csv").open("w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(HEALTH_HEADER)
    writer.writerows(health_rows)
  return capture


def can_row(mono_s, bus, returned, addr_hex, data_hex, src=None):
  if src is None:
    src = bus + (128 if returned else 0)
  return [0, f"{mono_s:.6f}", src, bus, int(returned), 0, addr_hex, "", len(bytes.fromhex(data_hex)), data_hex]


def health_row(mono_s, errors=0, resets=0, last_error="No error", last_data_error="No error", canfd=0, brs=0):
  return [0, f"{mono_s:.6f}", errors, resets, 0, 0, 0, 0, last_error, last_data_error, canfd, brs]


def event_row(mono_s, event, details="{}"):
  return [0, f"{mono_s:.6f}", event, "keyboard", "", 0, 0, "", "", "", details]


def test_analyzer_classifies_bus2_transport_health_delta(tmp_path):
  capture = write_capture(
    tmp_path,
    [
      can_row(0.100, 2, True, "0x123", "0000000000000000"),
      can_row(2.000, 2, False, "0x38D", "00004900a37ffea5"),
    ],
    [
      health_row(0.000),
      health_row(1.900, errors=5, resets=1, last_data_error="AckError"),
    ],
  )

  result = analyzer.analyze_capture(capture)

  assert len(result.fail_windows) == 1
  window = result.fail_windows[0]
  assert window.classification == "bus_error_or_load"
  assert "bus2_total_error_cnt" in window.bus2_error_deltas_pre
  assert window.failinfo_values == {3: 1}


def test_analyzer_does_not_treat_historical_errors_as_first_cause(tmp_path):
  capture = write_capture(
    tmp_path,
    [
      can_row(0.9995, 2, True, "0x123", "0000000000000000"),
      can_row(1.0000, 2, False, "0x38D", "00004900a37ffea5"),
    ],
    [
      health_row(0.000, errors=10, last_error="AckError"),
      health_row(0.900, errors=10, last_error="AckError"),
    ],
  )

  result = analyzer.analyze_capture(capture)

  window = result.fail_windows[0]
  assert window.classification == "bus_error_or_load"
  assert window.first_causal_event == "high bus-2 returned load in pre-window: 2000.0 fps"
  assert "historical bus-2 error state present, but no bus-2 error growth found near the window" in window.evidence


def test_analyzer_classifies_scc_leak_before_fail_window(tmp_path):
  capture = write_capture(
    tmp_path,
    [
      can_row(1.000, 0, False, "0x420", "800059c8b4406a00"),
      can_row(1.050, 0, True, "0x420", "800059c8b4406a00"),
      can_row(1.200, 2, False, "0x38D", "00004900a37ffea5"),
    ],
    [
      health_row(0.000),
      health_row(1.100),
    ],
  )

  result = analyzer.analyze_capture(capture)

  assert len(result.fail_windows) == 1
  window = result.fail_windows[0]
  assert window.classification == "scc_duplicate_leak"
  assert window.scc_leak_count == 1


def test_analyzer_classifies_escc_aeb_fields_before_fail_window(tmp_path):
  capture = write_capture(
    tmp_path,
    [
      can_row(1.000, 0, True, "0x2AB", "0100000000000000"),
      can_row(1.200, 2, False, "0x38D", "00004900a37ffea5"),
    ],
    [
      health_row(0.000),
      health_row(1.100),
    ],
  )

  result = analyzer.analyze_capture(capture)

  assert len(result.fail_windows) == 1
  assert result.fail_windows[0].classification == "escc_0x2ab_aeb_fields"


def test_analyzer_classifies_escc_diag_mode_fault_before_fail_window(tmp_path):
  capture = write_capture(
    tmp_path,
    [
      can_row(1.000, 0, True, "0x2AD", "0300010201090000"),
      can_row(1.200, 2, False, "0x38D", "00004900a37ffea5"),
    ],
    [
      health_row(0.000),
      health_row(1.100),
    ],
  )

  result = analyzer.analyze_capture(capture)

  assert len(result.fail_windows) == 1
  assert result.fail_windows[0].classification == "fdcan_mode_config"


def test_analyzer_reports_clean_capture_without_fail_windows(tmp_path):
  capture = write_capture(
    tmp_path,
    [can_row(1.000, 2, False, "0x38D", "00004900007ffea5")],
    [health_row(0.000)],
  )

  result = analyzer.analyze_capture(capture)

  assert result.fail_windows == []
  assert result.summary["fail_window_count"] == 0


def test_analyzer_reports_manual_chime_offsets_near_fail_window(tmp_path):
  capture = write_capture(
    tmp_path,
    [can_row(1.200, 2, False, "0x38D", "00004900a37ffea5")],
    [health_row(0.000), health_row(1.100)],
    [event_row(1.350, "manual_fca_chime", '{"key":"space","meaning":"heard_fca_chime"}')],
  )

  result = analyzer.analyze_capture(capture)

  assert result.summary["manual_chime_count"] == 1
  assert result.fail_windows[0].manual_chime_offsets_s == [0.15]
  assert result.fail_windows[0].classification == "unexplained_or_suppression_candidate"
