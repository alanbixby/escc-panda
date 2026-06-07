#!/usr/bin/env python3
import argparse
import csv
import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


CAR_BUS = 0
RADAR_BUS = 2

FCA11_ADDR = 0x38D
SCC12_ADDR = 0x421
ESCC_ADDR = 0x2AB
ESCC_DIAG_ADDR = 0x2AD
SCC_ADDRS = {0x420, 0x421, 0x50A, 0x389}

HEALTH_DELTA_KEYS = (
  "bus2_total_error_cnt",
  "bus2_can_core_reset_count",
  "bus2_bus_off_cnt",
  "bus2_total_tx_lost_cnt",
  "bus2_total_rx_lost_cnt",
  "bus2_total_tx_checksum_error_cnt",
)
LOGGER_EVENT_NAMES = {"manual_fca_chime"}


@dataclass
class TrafficRates:
  window_s: float
  bus2_returned_fps: float = 0.0
  bus2_physical_fps: float = 0.0
  bus0_returned_fps: float = 0.0
  bus0_physical_fps: float = 0.0
  bus2_returned_frames: int = 0
  bus2_physical_frames: int = 0
  bus0_returned_frames: int = 0
  bus0_physical_frames: int = 0


@dataclass
class FailWindow:
  start_s: float
  end_s: float
  frame_count: int
  failinfo_values: dict[int, int]
  pre_window_rates: TrafficRates
  scc_leak_count: int
  bus2_error_deltas_pre: dict[str, Any]
  bus2_error_deltas_window: dict[str, Any]
  first_causal_event: str
  classification: str
  manual_chime_offsets_s: list[float] = field(default_factory=list)
  evidence: list[str] = field(default_factory=list)


@dataclass
class CaptureAnalysis:
  capture: str
  duration_s: float
  frames: int
  fail_windows: list[FailWindow]
  summary: dict[str, Any]


def bits_le(dat: bytes, start: int, length: int) -> int:
  raw = int.from_bytes(dat.ljust(8, b"\x00"), "little")
  return (raw >> start) & ((1 << length) - 1)


def decode_fca11(dat: bytes) -> dict[str, int | str]:
  if len(dat) < 8:
    return {"decode_error": f"short_frame_{len(dat)}"}
  return {
    "CF_VSM_Warn": bits_le(dat, 3, 2),
    "CR_VSM_DecCmd": bits_le(dat, 8, 8),
    "FCA_Status": bits_le(dat, 18, 2),
    "FCA_CmdAct": bits_le(dat, 20, 1),
    "FCA_StopReq": bits_le(dat, 21, 1),
    "FCA_DrvSetStatus": bits_le(dat, 22, 3),
    "CF_VSM_DecCmdAct": bits_le(dat, 31, 1),
    "FCA_Failinfo": bits_le(dat, 32, 3),
    "CR_FCA_Alive": bits_le(dat, 35, 4),
  }


def decode_scc12(dat: bytes) -> dict[str, int | str]:
  if len(dat) < 8:
    return {"decode_error": f"short_frame_{len(dat)}"}
  return {
    "CF_VSM_Warn": bits_le(dat, 4, 2),
    "CF_VSM_DecCmdAct": bits_le(dat, 1, 1),
    "CR_VSM_DecCmd": bits_le(dat, 16, 8),
    "ACCFailInfo": bits_le(dat, 11, 2),
    "ACCMode": bits_le(dat, 13, 2),
    "AEB_Failinfo": bits_le(dat, 50, 2),
    "AEB_Status": bits_le(dat, 52, 2),
    "AEB_CmdAct": bits_le(dat, 54, 1),
  }


def decode_escc(dat: bytes) -> dict[str, int | str]:
  if len(dat) < 8:
    return {"decode_error": f"short_frame_{len(dat)}"}
  return {
    "FCA_CmdAct": bits_le(dat, 0, 1),
    "CF_VSM_Warn_FCA11": bits_le(dat, 1, 2),
    "AEB_CmdAct": bits_le(dat, 3, 1),
    "CF_VSM_Warn_SCC12": bits_le(dat, 4, 2),
    "CF_VSM_DecCmdAct_SCC12": bits_le(dat, 6, 1),
    "CF_VSM_DecCmdAct_FCA11": bits_le(dat, 7, 1),
    "CR_VSM_DecCmd_SCC12": bits_le(dat, 8, 8),
    "CR_VSM_DecCmd_FCA11": bits_le(dat, 56, 8),
  }


def decode_escc_diag(dat: bytes) -> dict[str, int | str]:
  if len(dat) < 8:
    return {"decode_error": f"short_frame_{len(dat)}"}

  page = dat[0]
  if page == 0:
    return {
      "diag_page": page,
      "car_to_radar_forwarded": int.from_bytes(dat[1:3], "little"),
      "radar_to_car_forwarded": int.from_bytes(dat[3:5], "little"),
      "scc_blocked_car_to_radar": int.from_bytes(dat[5:7], "little"),
      "rolling_counter": dat[7],
    }
  if page == 1:
    return {
      "diag_page": page,
      "scc_blocked_radar_to_car": int.from_bytes(dat[1:3], "little"),
      "queue_pressure_drops": int.from_bytes(dat[3:5], "little"),
      "canfd_frames_dropped": int.from_bytes(dat[5:7], "little"),
      "rolling_counter": dat[7],
    }
  if page == 2:
    return {
      "diag_page": page,
      "non_scc_car_to_radar_frames": int.from_bytes(dat[1:3], "little"),
      "fca11_fail_frames_bus2": int.from_bytes(dat[3:5], "little"),
      "bus2_tx_queue_free_slots": dat[5],
      "bus2_transmit_error_cnt": dat[6],
      "rolling_counter": dat[7],
    }
  if page == 3:
    return {
      "diag_page": page,
      "logical_bus0_can_core": dat[1],
      "logical_bus1_can_core": dat[2],
      "logical_bus2_can_core": dat[3],
      "harness_status": dat[4],
      "radar_bus_dar": dat[5] & 0x1,
      "radar_bus_fdoe": (dat[5] >> 1) & 0x1,
      "radar_bus_brse": (dat[5] >> 2) & 0x1,
      "car_bus_fdoe": (dat[5] >> 3) & 0x1,
      "car_bus_brse": (dat[5] >> 4) & 0x1,
      "traffic_shape_enabled": (dat[5] >> 5) & 0x1,
      "bus2_tx_queue_free_slots": dat[6],
      "bus2_transmit_error_cnt": dat[7],
    }
  return {"diag_page": page}


def fca11_actuation(fields: dict[str, Any]) -> bool:
  return bool(fields.get("CF_VSM_Warn") or fields.get("CR_VSM_DecCmd") or fields.get("FCA_CmdAct") or fields.get("CF_VSM_DecCmdAct"))


def scc12_actuation_or_fail(fields: dict[str, Any]) -> bool:
  return bool(
    fields.get("CF_VSM_Warn")
    or fields.get("CF_VSM_DecCmdAct")
    or fields.get("CR_VSM_DecCmd")
    or fields.get("ACCFailInfo")
    or fields.get("AEB_Failinfo")
    or fields.get("AEB_Status")
    or fields.get("AEB_CmdAct")
  )


def escc_aeb_fields_active(fields: dict[str, Any]) -> bool:
  return bool(
    fields.get("FCA_CmdAct")
    or fields.get("CF_VSM_Warn_FCA11")
    or fields.get("AEB_CmdAct")
    or fields.get("CF_VSM_Warn_SCC12")
    or fields.get("CF_VSM_DecCmdAct_SCC12")
    or fields.get("CF_VSM_DecCmdAct_FCA11")
    or fields.get("CR_VSM_DecCmd_SCC12")
    or fields.get("CR_VSM_DecCmd_FCA11")
  )


def parse_addr(addr_hex: str) -> int:
  return int(addr_hex, 16)


def parse_bool_int(value: str) -> bool:
  return bool(int(value))


def parse_number(value: Any) -> int | float | None:
  if value is None or value == "":
    return None
  try:
    return int(value)
  except (TypeError, ValueError):
    try:
      return float(value)
    except (TypeError, ValueError):
      return None


def delta_dict(before: dict[str, Any] | None, after: dict[str, Any] | None, keys: tuple[str, ...] = HEALTH_DELTA_KEYS) -> dict[str, Any]:
  if before is None or after is None:
    return {}

  ret: dict[str, Any] = {}
  for key in keys:
    old = parse_number(before.get(key))
    new = parse_number(after.get(key))
    if old is None or new is None:
      continue
    delta = new - old
    if delta != 0:
      ret[key] = {"old": old, "new": new, "delta": delta}
  return ret


def health_at_or_before(rows: list[dict[str, Any]], t: float) -> dict[str, Any] | None:
  ret = None
  for row in rows:
    if float(row["mono_s"]) <= t:
      ret = row
    else:
      break
  return ret


def first_health_near_or_after(rows: list[dict[str, Any]], t: float, slack_s: float = 1.0) -> dict[str, Any] | None:
  for row in rows:
    mono_s = float(row["mono_s"])
    if mono_s >= t and mono_s <= t + slack_s:
      return row
  return None


def load_health(capture_dir: Path) -> tuple[list[dict[str, Any]], list[tuple[float, str, dict[str, Any]]]]:
  health_path = capture_dir / "health.csv"
  if not health_path.exists():
    return [], []

  rows: list[dict[str, Any]] = []
  delta_events: list[tuple[float, str, dict[str, Any]]] = []
  with health_path.open(newline="") as f:
    prev = None
    for row in csv.DictReader(f):
      rows.append(row)
      if prev is not None:
        deltas = delta_dict(prev, row)
        positive = {k: v for k, v in deltas.items() if v["delta"] > 0}
        if positive:
          delta_events.append((float(row["mono_s"]), "bus2_error_delta", positive))
      prev = row
  return rows, delta_events


def load_logger_events(capture_dir: Path) -> list[tuple[float, str, dict[str, Any]]]:
  events_path = capture_dir / "events.csv"
  if not events_path.exists():
    return []

  events: list[tuple[float, str, dict[str, Any]]] = []
  with events_path.open(newline="") as f:
    for row in csv.DictReader(f):
      event = row.get("event", "")
      if event not in LOGGER_EVENT_NAMES:
        continue

      details: dict[str, Any] = {}
      if row.get("details"):
        try:
          decoded = json.loads(row["details"])
        except json.JSONDecodeError:
          decoded = {"raw_details": row["details"]}
        if isinstance(decoded, dict):
          details = decoded
      events.append((float(row["mono_s"]), event, details))
  return events


def traffic_rates(frames: list[tuple[float, int, bool, bool, int]], start_s: float, end_s: float) -> TrafficRates:
  actual_window_s = max(0.0, end_s - start_s)
  counts = Counter()
  for mono_s, bus, returned, _rejected, _addr in frames:
    if start_s <= mono_s < end_s:
      counts[(bus, returned)] += 1

  denom = actual_window_s if actual_window_s > 0.0 else 1.0
  return TrafficRates(
    window_s=actual_window_s,
    bus2_returned_fps=counts[(RADAR_BUS, True)] / denom,
    bus2_physical_fps=counts[(RADAR_BUS, False)] / denom,
    bus0_returned_fps=counts[(CAR_BUS, True)] / denom,
    bus0_physical_fps=counts[(CAR_BUS, False)] / denom,
    bus2_returned_frames=counts[(RADAR_BUS, True)],
    bus2_physical_frames=counts[(RADAR_BUS, False)],
    bus0_returned_frames=counts[(CAR_BUS, True)],
    bus0_physical_frames=counts[(CAR_BUS, False)],
  )


def find_between(events: list[tuple[float, str, dict[str, Any]]], start_s: float, end_s: float) -> list[tuple[float, str, dict[str, Any]]]:
  return [event for event in events if start_s <= event[0] <= end_s]


def summarize_event(event: tuple[float, str, dict[str, Any]], window_start_s: float) -> str:
  t, name, details = event
  details_s = json.dumps(details, sort_keys=True, separators=(",", ":"))
  return f"{name} at {t:.3f}s ({window_start_s - t:+.3f}s before window): {details_s}"


def classify_window(
  window_start_s: float,
  rates: TrafficRates,
  pre_deltas: dict[str, Any],
  window_deltas: dict[str, Any],
  health_start: dict[str, Any] | None,
  events_pre: list[tuple[float, str, dict[str, Any]]],
  scc_leak_count: int,
) -> tuple[str, str, list[str]]:
  evidence: list[str] = []
  candidates: list[tuple[float, str, str]] = []

  initial_health = health_start or {}
  initial_error_count = parse_number(initial_health.get("bus2_total_error_cnt")) or 0
  initial_reset_count = parse_number(initial_health.get("bus2_can_core_reset_count")) or 0
  initial_last_error = initial_health.get("bus2_last_stored_error")
  initial_last_data_error = initial_health.get("bus2_last_data_stored_error")
  active_error_warning = parse_number(initial_health.get("bus2_error_warning")) or 0
  active_error_passive = parse_number(initial_health.get("bus2_error_passive")) or 0
  active_bus_off = parse_number(initial_health.get("bus2_bus_off")) or 0
  current_receive_errors = parse_number(initial_health.get("bus2_receive_error_cnt")) or 0
  current_transmit_errors = parse_number(initial_health.get("bus2_transmit_error_cnt")) or 0

  bad_initial_error = initial_last_error not in (None, "", "No error", "NoChange")
  bad_initial_data_error = initial_last_data_error not in (None, "", "No error", "NoChange")
  active_error_state = bool(active_bus_off or active_error_warning or active_error_passive or current_receive_errors or current_transmit_errors)
  historical_error_state = bool(initial_error_count or initial_reset_count or bad_initial_error or bad_initial_data_error)
  if pre_deltas or window_deltas or active_error_state:
    evidence.append("bus-2 health already bad or changed around the window")
    for event in events_pre:
      if event[1] == "bus2_error_delta":
        candidates.append((event[0], "bus_error_or_load", summarize_event(event, window_start_s)))
    if not candidates:
      candidates.append((window_start_s, "bus_error_or_load", "bus-2 error/reset state present at first health sample"))
  elif historical_error_state:
    evidence.append("historical bus-2 error state present, but no bus-2 error growth found near the window")

  if rates.bus2_returned_fps >= 1000.0:
    evidence.append(f"high pre-window bus-2 returned load: {rates.bus2_returned_fps:.1f} fps")
    candidates.append((window_start_s, "bus_error_or_load", f"high bus-2 returned load in pre-window: {rates.bus2_returned_fps:.1f} fps"))

  canfd_enabled = parse_number(initial_health.get("bus2_canfd_enabled")) or 0
  brs_enabled = parse_number(initial_health.get("bus2_brs_enabled")) or 0
  if canfd_enabled or brs_enabled:
    evidence.append(f"bus-2 health reports CAN-FD/BRS enabled: canfd={canfd_enabled} brs={brs_enabled}")
    candidates.append((window_start_s, "fdcan_mode_config", "bus-2 CAN-FD/BRS enabled in health snapshot"))

  for event in events_pre:
    if event[1] == "escc_diag_mode_fault":
      evidence.append("ESCC_DIAG register snapshot showed DAR/FDOE/BRSE mismatch")
      candidates.append((event[0], "fdcan_mode_config", summarize_event(event, window_start_s)))

  if scc_leak_count > 0:
    evidence.append(f"{scc_leak_count} radar SCC frame(s) forwarded to car inside the 150 ms SCC block window")
    for event in events_pre:
      if event[1] == "scc_leak":
        candidates.append((event[0], "scc_duplicate_leak", summarize_event(event, window_start_s)))

  for event in events_pre:
    if event[1] == "escc_aeb_fields":
      evidence.append("ESCC 0x2AB warning/decel fields were nonzero before physical FCA fail")
      candidates.append((event[0], "escc_0x2ab_aeb_fields", summarize_event(event, window_start_s)))

  if candidates:
    candidates.sort(key=lambda item: item[0])
    # Prefer concrete transport health over high-load if both occur at the same capture-start timestamp.
    transport = [candidate for candidate in candidates if candidate[1] == "bus_error_or_load"]
    chosen = transport[0] if transport else candidates[0]
    return chosen[1], chosen[2], evidence

  evidence.append("clean transport and no SCC leak or 0x2AB precursor found in available pre-window")
  return "unexplained_or_suppression_candidate", "none found before window", evidence


def analyze_capture(capture_dir: Path, pre_window_s: float = 2.0, fail_gap_s: float = 0.5) -> CaptureAnalysis:
  can_path = capture_dir / "can.csv"
  if not can_path.exists():
    raise FileNotFoundError(can_path)

  health_rows, health_delta_events = load_health(capture_dir)
  traffic: list[tuple[float, int, bool, bool, int]] = []
  fail_frames: list[tuple[float, dict[str, Any]]] = []
  logger_events = load_logger_events(capture_dir)
  events: list[tuple[float, str, dict[str, Any]]] = [*health_delta_events, *logger_events]
  last_car_scc_s: float | None = None
  diag_pages: dict[int, dict[str, Any]] = {}

  first_frame_s: float | None = None
  last_frame_s = 0.0
  frame_count = 0

  with can_path.open(newline="") as f:
    for row in csv.DictReader(f):
      frame_count += 1
      mono_s = float(row["mono_s"])
      first_frame_s = mono_s if first_frame_s is None else first_frame_s
      last_frame_s = mono_s
      bus = int(row["bus"])
      returned = parse_bool_int(row["returned"])
      rejected = parse_bool_int(row["rejected"])
      addr = parse_addr(row["addr_hex"])
      dat = bytes.fromhex(row["data_hex"])

      traffic.append((mono_s, bus, returned, rejected, addr))

      if addr in SCC_ADDRS and bus == CAR_BUS and not returned and not rejected:
        last_car_scc_s = mono_s

      if addr in SCC_ADDRS and bus == CAR_BUS and returned and last_car_scc_s is not None:
        delta_s = mono_s - last_car_scc_s
        if 0.0 <= delta_s <= 0.150:
          events.append((mono_s, "scc_leak", {"addr": f"0x{addr:X}", "seconds_after_physical_car_scc": round(delta_s, 6)}))

      if addr == FCA11_ADDR and bus == RADAR_BUS and not returned and not rejected:
        fields = decode_fca11(dat)
        if fields.get("FCA_Failinfo", 0):
          fail_frames.append((mono_s, fields))
        elif fca11_actuation(fields):
          events.append((mono_s, "physical_fca11_actuation", fields))

      elif addr == SCC12_ADDR and bus == RADAR_BUS and not returned and not rejected:
        fields = decode_scc12(dat)
        if scc12_actuation_or_fail(fields):
          events.append((mono_s, "physical_scc12_fields", fields))

      elif addr == ESCC_ADDR:
        fields = decode_escc(dat)
        if escc_aeb_fields_active(fields):
          events.append((mono_s, "escc_aeb_fields", fields))

      elif addr == ESCC_DIAG_ADDR:
        fields = decode_escc_diag(dat)
        page = fields.get("diag_page")
        if isinstance(page, int):
          diag_pages[page] = fields
        if (
          fields.get("radar_bus_dar") == 0
          or fields.get("radar_bus_fdoe")
          or fields.get("radar_bus_brse")
          or fields.get("car_bus_fdoe")
          or fields.get("car_bus_brse")
        ):
          events.append((mono_s, "escc_diag_mode_fault", fields))

  grouped: list[list[tuple[float, dict[str, Any]]]] = []
  for frame in fail_frames:
    if not grouped or frame[0] - grouped[-1][-1][0] > fail_gap_s:
      grouped.append([frame])
    else:
      grouped[-1].append(frame)

  fail_windows: list[FailWindow] = []
  capture_start = first_frame_s or 0.0
  for group in grouped:
    start_s = group[0][0]
    end_s = group[-1][0]
    pre_start_s = max(capture_start, start_s - pre_window_s)
    rates = traffic_rates(traffic, pre_start_s, start_s)
    pre_health_before = health_at_or_before(health_rows, pre_start_s)
    health_at_start = health_at_or_before(health_rows, start_s) or first_health_near_or_after(health_rows, start_s)
    health_at_end = health_at_or_before(health_rows, end_s) or first_health_near_or_after(health_rows, end_s)
    pre_deltas = delta_dict(pre_health_before, health_at_start)
    window_deltas = delta_dict(health_at_start, health_at_end)
    events_pre = find_between(events, pre_start_s, start_s)
    scc_leak_count = sum(1 for event in events_pre if event[1] == "scc_leak")
    manual_chime_offsets = [
      round(event[0] - start_s, 6)
      for event in find_between(events, pre_start_s, end_s + pre_window_s)
      if event[1] == "manual_fca_chime"
    ]
    classification, first_causal, evidence = classify_window(start_s, rates, pre_deltas, window_deltas, health_at_start, events_pre, scc_leak_count)

    fail_windows.append(
      FailWindow(
        start_s=start_s,
        end_s=end_s,
        frame_count=len(group),
        failinfo_values=dict(Counter(int(frame[1]["FCA_Failinfo"]) for frame in group)),
        pre_window_rates=rates,
        scc_leak_count=scc_leak_count,
        bus2_error_deltas_pre=pre_deltas,
        bus2_error_deltas_window=window_deltas,
        first_causal_event=first_causal,
        classification=classification,
        manual_chime_offsets_s=manual_chime_offsets,
        evidence=evidence,
      )
    )

  summary = {
    "fail_window_count": len(fail_windows),
    "fail_frame_count": len(fail_frames),
    "classifications": dict(Counter(window.classification for window in fail_windows)),
    "diag_pages_seen": sorted(diag_pages),
    "traffic_shape_enabled": bool(diag_pages.get(3, {}).get("traffic_shape_enabled", 0)),
    "manual_chime_count": sum(1 for event in logger_events if event[1] == "manual_fca_chime"),
  }
  return CaptureAnalysis(
    capture=str(capture_dir),
    duration_s=max(0.0, last_frame_s - capture_start),
    frames=frame_count,
    fail_windows=fail_windows,
    summary=summary,
  )


def analysis_to_jsonable(analysis: CaptureAnalysis) -> dict[str, Any]:
  ret = asdict(analysis)
  for window in ret["fail_windows"]:
    window["pre_window_rates"] = dict(window["pre_window_rates"])
  return ret


def print_text(analyses: list[CaptureAnalysis]) -> None:
  for analysis in analyses:
    print(f"\n{analysis.capture}")
    manual_chimes = analysis.summary.get("manual_chime_count", 0)
    traffic_shape = analysis.summary.get("traffic_shape_enabled", False)
    print(
      f"  duration={analysis.duration_s:.3f}s frames={analysis.frames} "
      + f"fail_windows={len(analysis.fail_windows)} manual_chimes={manual_chimes} traffic_shape={traffic_shape}"
    )
    if not analysis.fail_windows:
      print("  no physical bus-2 FCA11.FCA_Failinfo windows")
      continue

    for idx, window in enumerate(analysis.fail_windows, start=1):
      rates = window.pre_window_rates
      window_line = (
        f"  window {idx}: {window.start_s:.3f}-{window.end_s:.3f}s "
        + f"frames={window.frame_count} failinfo={window.failinfo_values} classification={window.classification}"
      )
      rates_line = (
        f"    pre-rate bus2_returned={rates.bus2_returned_fps:.1f}/s "
        + f"bus2_physical={rates.bus2_physical_fps:.1f}/s bus0_returned={rates.bus0_returned_fps:.1f}/s "
        + f"bus0_physical={rates.bus0_physical_fps:.1f}/s"
      )
      print(window_line)
      print(rates_line)
      print(f"    scc_leaks={window.scc_leak_count} first={window.first_causal_event}")
      if window.manual_chime_offsets_s:
        offsets = ", ".join(f"{offset:+.3f}s" for offset in window.manual_chime_offsets_s)
        print(f"    manual_fca_chime_offsets_from_window_start=[{offsets}]")
      if window.bus2_error_deltas_pre:
        print(f"    bus2_error_deltas_pre={json.dumps(window.bus2_error_deltas_pre, sort_keys=True)}")
      if window.bus2_error_deltas_window:
        print(f"    bus2_error_deltas_window={json.dumps(window.bus2_error_deltas_window, sort_keys=True)}")
      for item in window.evidence:
        print(f"    evidence: {item}")


def discover_captures(paths: list[Path]) -> list[Path]:
  captures: list[Path] = []
  for path in paths:
    path = path.expanduser()
    if path.is_file() and path.name == "can.csv":
      captures.append(path.parent)
    elif path.is_dir() and (path / "can.csv").exists():
      captures.append(path)
    elif path.is_dir():
      captures.extend(sorted(child for child in path.iterdir() if (child / "can.csv").exists()))
  return sorted(set(captures))


def main() -> int:
  parser = argparse.ArgumentParser(description="Analyze ESCC/FCA capture folders for physical radar FCA fail windows.")
  parser.add_argument("paths", nargs="*", type=Path, default=[Path("~/escc-fca-logs")], help="capture folder(s), can.csv file(s), or a parent log directory")
  parser.add_argument("--pre-window", type=float, default=2.0, help="seconds before each FCA fail window used for rates and precursor events")
  parser.add_argument("--fail-gap", type=float, default=0.5, help="maximum gap between FCA fail frames in one window")
  parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
  args = parser.parse_args()

  captures = discover_captures(args.paths)
  if not captures:
    print("No capture folders found.", file=sys.stderr)
    return 2

  analyses = [analyze_capture(capture, pre_window_s=args.pre_window, fail_gap_s=args.fail_gap) for capture in captures]
  if args.json:
    print(json.dumps([analysis_to_jsonable(analysis) for analysis in analyses], indent=2, sort_keys=True))
  else:
    print_text(analyses)
  return 0


if __name__ == "__main__":
  sys.exit(main())
