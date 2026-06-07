#!/usr/bin/env python3
import argparse
import csv
import json
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

try:
  from panda import Panda
except ModuleNotFoundError:
  sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
  from python import Panda


CAR_BUS = 0
RADAR_BUS = 2

SCC_ADDRS = {0x420, 0x421, 0x50A, 0x389}
FCA_ADDRS = {0x38D, 0x483}
KEEPALIVE_ADDRS = {0x260, 0x2B0, 0x371, 0x386, 0x394}
WATCH_ADDRS = SCC_ADDRS | FCA_ADDRS | KEEPALIVE_ADDRS | {0x2AB}

ADDR_NAMES = {
  0x260: "EMS16",
  0x2AB: "ESCC_OUT",
  0x2B0: "SAS11",
  0x371: "GAS_ALT",
  0x386: "WHL_SPD11",
  0x389: "SCC14",
  0x38D: "FCA11",
  0x394: "TCS13",
  0x420: "SCC11",
  0x421: "SCC12",
  0x483: "FCA12",
  0x50A: "SCC13",
}

GLOBAL_HEALTH_KEYS = (
  "uptime",
  "voltage",
  "current",
  "safety_tx_blocked",
  "safety_rx_invalid",
  "tx_buffer_overflow",
  "rx_buffer_overflow",
  "faults",
  "ignition_line",
  "ignition_can",
  "controls_allowed",
  "safety_mode",
  "safety_param",
  "fault_status",
  "heartbeat_lost",
  "interrupt_load",
  "safety_rx_checks_invalid",
)

CAN_HEALTH_KEYS = (
  "bus_off",
  "bus_off_cnt",
  "error_warning",
  "error_passive",
  "last_error",
  "last_stored_error",
  "last_data_error",
  "last_data_stored_error",
  "receive_error_cnt",
  "transmit_error_cnt",
  "total_error_cnt",
  "total_tx_lost_cnt",
  "total_rx_lost_cnt",
  "total_tx_cnt",
  "total_rx_cnt",
  "total_fwd_cnt",
  "total_tx_checksum_error_cnt",
  "can_speed",
  "can_data_speed",
  "canfd_enabled",
  "brs_enabled",
  "can_core_reset_count",
)

HEALTH_EVENT_KEYS = (
  "safety_tx_blocked",
  "safety_rx_invalid",
  "tx_buffer_overflow",
  "rx_buffer_overflow",
  "faults",
  "fault_status",
  "heartbeat_lost",
  "safety_rx_checks_invalid",
)

CAN_HEALTH_EVENT_KEYS = (
  "bus_off",
  "bus_off_cnt",
  "error_warning",
  "error_passive",
  "last_stored_error",
  "last_data_stored_error",
  "receive_error_cnt",
  "transmit_error_cnt",
  "total_error_cnt",
  "total_tx_lost_cnt",
  "total_rx_lost_cnt",
  "total_tx_checksum_error_cnt",
  "canfd_enabled",
  "brs_enabled",
  "can_core_reset_count",
)


def git_info() -> dict:
  def run_git(args: list[str]) -> str | None:
    try:
      return subprocess.check_output(["git", *args], text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
      return None

  return {
    "head": run_git(["rev-parse", "HEAD"]),
    "status_short": run_git(["status", "--short"]),
  }


def decode_src(src: int) -> tuple[int, bool, bool]:
  return src & 0x7, 128 <= src < 192, src >= 192


def now_fields(start_mono: int) -> tuple[int, float]:
  mono_ns = time.monotonic_ns()
  return time.time_ns(), (mono_ns - start_mono) / 1e9


def decode_fca11(dat: bytes) -> dict:
  if len(dat) < 4:
    return {"decode_error": f"short_frame_{len(dat)}"}
  return {
    "cf_vsm_warn_fca11": (dat[0] >> 3) & 0x3,
    "cr_vsm_deccmd_fca11": dat[1],
    "fca_cmd_act": (dat[2] >> 4) & 0x1,
    "cf_vsm_deccmdact_fca11": (dat[3] >> 7) & 0x1,
  }


def decode_fca12(dat: bytes) -> dict:
  if len(dat) < 1:
    return {"decode_error": f"short_frame_{len(dat)}"}
  return {
    "fca_usm": dat[0] & 0x7,
    "fca_drv_set_state": (dat[0] >> 3) & 0x7,
  }


def decode_scc12(dat: bytes) -> dict:
  if len(dat) < 7:
    return {"decode_error": f"short_frame_{len(dat)}"}
  return {
    "cf_vsm_warn_scc12": (dat[0] >> 4) & 0x3,
    "cf_vsm_deccmdact_scc12": (dat[0] >> 1) & 0x1,
    "cr_vsm_deccmd_scc12": dat[2],
    "aeb_cmd_act": (dat[6] >> 6) & 0x1,
  }


def decode_escc_out(dat: bytes) -> dict:
  if len(dat) < 8:
    return {"decode_error": f"short_frame_{len(dat)}"}
  return {
    "fca_cmd_act": dat[0] & 0x1,
    "cf_vsm_warn_fca11": (dat[0] >> 1) & 0x3,
    "aeb_cmd_act": (dat[0] >> 3) & 0x1,
    "cf_vsm_warn_scc12": (dat[0] >> 4) & 0x3,
    "cf_vsm_deccmdact_scc12": (dat[0] >> 6) & 0x1,
    "cf_vsm_deccmdact_fca11": (dat[0] >> 7) & 0x1,
    "cr_vsm_deccmd_scc12": dat[1],
    "cr_vsm_deccmd_fca11": dat[7],
  }


def active_fca11_actuation(fields: dict) -> bool:
  return bool(fields.get("fca_cmd_act") or fields.get("cf_vsm_deccmdact_fca11") or fields.get("cr_vsm_deccmd_fca11"))


def active_scc12_actuation(fields: dict) -> bool:
  return bool(fields.get("aeb_cmd_act") or fields.get("cf_vsm_deccmdact_scc12") or fields.get("cr_vsm_deccmd_scc12"))


def active_escc_warning_or_actuation(fields: dict) -> bool:
  return bool(
    fields.get("fca_cmd_act")
    or fields.get("aeb_cmd_act")
    or fields.get("cf_vsm_deccmdact_scc12")
    or fields.get("cf_vsm_deccmdact_fca11")
    or fields.get("cr_vsm_deccmd_scc12")
    or fields.get("cr_vsm_deccmd_fca11")
    or fields.get("cf_vsm_warn_scc12")
  )


def event_details(fields: dict) -> str:
  return json.dumps(fields, sort_keys=True, separators=(",", ":"))


def snapshot_health(panda: Panda) -> tuple[dict, dict[int, dict]]:
  return panda.health(), {bus: panda.can_health(bus) for bus in (CAR_BUS, RADAR_BUS)}


def write_health_row(writer: csv.writer, start_mono: int, global_health: dict, can_health: dict[int, dict]) -> None:
  unix_ns, mono_s = now_fields(start_mono)
  row = [unix_ns, f"{mono_s:.6f}"]
  row += [global_health.get(key) for key in GLOBAL_HEALTH_KEYS]
  for bus in (CAR_BUS, RADAR_BUS):
    row += [can_health[bus].get(key) for key in CAN_HEALTH_KEYS]
  writer.writerow(row)


def build_health_header() -> list[str]:
  header = ["unix_ns", "mono_s", *GLOBAL_HEALTH_KEYS]
  for bus in (CAR_BUS, RADAR_BUS):
    header += [f"bus{bus}_{key}" for key in CAN_HEALTH_KEYS]
  return header


def main() -> int:
  parser = argparse.ArgumentParser(description="Passive ESCC/FCA CAN capture with automatic event tags.")
  parser.add_argument("--out", default="escc-fca-logs", help="directory where one timestamped capture folder is created")
  parser.add_argument("--serial", help="panda serial; omit to use the normal panda selector")
  parser.add_argument("--health-period", type=float, default=0.5, help="seconds between health snapshots")
  parser.add_argument("--gap", type=float, default=0.25, help="tag watched-message gaps longer than this many seconds")
  parser.add_argument("--debounce", type=float, default=1.0, help="minimum seconds between duplicate event tags")
  parser.add_argument("--force-classic-can", action="store_true", help="set CAN-FD data speed low on buses 0 and 2 before capture")
  args = parser.parse_args()

  start_wall_ns = time.time_ns()
  start_mono_ns = time.monotonic_ns()
  capture_dir = Path(args.out).expanduser() / time.strftime("%Y%m%d-%H%M%S")
  capture_dir.mkdir(parents=True, exist_ok=False)

  panda = Panda(serial=args.serial, cli=(args.serial is None))
  if args.force_classic_can:
    panda.set_can_data_speed_kbps(CAR_BUS, 10)
    panda.set_can_data_speed_kbps(RADAR_BUS, 10)
    time.sleep(1)

  meta = {
    "start_unix_ns": start_wall_ns,
    "start_time_local": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    "panda_serial": panda.get_serial(),
    "panda_usb_serial": panda.get_usb_serial(),
    "panda_version": panda.get_version(),
    "force_classic_can": args.force_classic_can,
    "git": git_info(),
  }
  (capture_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")

  raw_f = (capture_dir / "can.csv").open("w", newline="", buffering=1024 * 1024)
  events_f = (capture_dir / "events.csv").open("w", newline="")
  health_f = (capture_dir / "health.csv").open("w", newline="")

  raw_writer = csv.writer(raw_f)
  events_writer = csv.writer(events_f)
  health_writer = csv.writer(health_f)

  raw_writer.writerow(["unix_ns", "mono_s", "src", "bus", "returned", "rejected", "addr_hex", "name", "len", "data_hex"])
  events_writer.writerow(["unix_ns", "mono_s", "event", "src", "bus", "returned", "rejected", "addr_hex", "name", "data_hex", "details"])
  health_writer.writerow(build_health_header())

  counts = defaultdict(int)
  event_counts = defaultdict(int)
  last_event = defaultdict(lambda: -1e9)
  last_seen = {}
  last_status = {}
  unexpected_radar_tx_seen = set()
  seen_count = defaultdict(int)
  last_physical_car_scc = -1e9
  last_health_time = -1e9
  last_status_print = -1e9
  prev_global_health = None
  prev_can_health = None

  def tag(
    event: str,
    mono_s: float,
    src: int | str,
    bus: int | str,
    returned: bool,
    rejected: bool,
    addr: int | None,
    dat: bytes,
    details: dict,
    key: tuple | None = None,
  ) -> None:
    event_key = key if key is not None else (event, src, addr)
    if mono_s - last_event[event_key] < args.debounce:
      return
    last_event[event_key] = mono_s
    unix_ns = time.time_ns()
    addr_hex = "" if addr is None else f"0x{addr:X}"
    name = "" if addr is None else ADDR_NAMES.get(addr, "")
    events_writer.writerow([unix_ns, f"{mono_s:.6f}", event, src, bus, int(returned), int(rejected), addr_hex, name, dat.hex(), event_details(details)])
    events_f.flush()
    event_counts[event] += 1
    print(f"\n[{mono_s:9.3f}s] {event} {addr_hex} {event_details(details)}")

  print(f"Logging to {capture_dir}")
  print("Automatic tags: FCA/SCC/ESCC warning fields, watched-message gaps, SCC forwarding during the block window, and panda/CAN health changes.")
  print("Leave this running while you drive; stop with Ctrl-C after parking.")

  try:
    while True:
      messages = panda.can_recv()
      unix_ns = time.time_ns()
      mono_s = (time.monotonic_ns() - start_mono_ns) / 1e9

      for addr, dat, src in messages:
        bus, returned, rejected = decode_src(src)
        name = ADDR_NAMES.get(addr, "")
        counts[(bus, returned, rejected)] += 1
        raw_writer.writerow([unix_ns, f"{mono_s:.6f}", src, bus, int(returned), int(rejected), f"0x{addr:X}", name, len(dat), dat.hex()])

        if bus == RADAR_BUS and returned and addr not in KEEPALIVE_ADDRS and addr not in unexpected_radar_tx_seen:
          unexpected_radar_tx_seen.add(addr)
          tag(
            "unexpected_radar_tx",
            mono_s,
            src,
            bus,
            returned,
            rejected,
            addr,
            dat,
            {"expected": "bus 2 TX should only contain radar keepalive IDs"},
            key=("unexpected_radar_tx", addr),
          )

        if addr in WATCH_ADDRS:
          msg_key = (src, addr)
          if msg_key in last_seen and seen_count[msg_key] > 10:
            gap_s = mono_s - last_seen[msg_key]
            if gap_s > args.gap:
              tag("message_gap", mono_s, src, bus, returned, rejected, addr, dat, {"gap_s": round(gap_s, 6)}, key=("message_gap", src, addr))
          last_seen[msg_key] = mono_s
          seen_count[msg_key] += 1

        if addr == 0x38D:
          fields = decode_fca11(dat)
          status_key = ("fca11_status", bus, returned)
          status = fields.get("cf_vsm_warn_fca11")
          if status_key in last_status and status != last_status[status_key]:
            tag(
              "fca11_status_change",
              mono_s,
              src,
              bus,
              returned,
              rejected,
              addr,
              dat,
              {"old": last_status[status_key], "new": status},
              key=(*status_key, last_status[status_key], status),
            )
          last_status[status_key] = status
          if active_fca11_actuation(fields):
            tag("fca11_actuation_fields", mono_s, src, bus, returned, rejected, addr, dat, fields, key=("fca11_actuation_fields", bus, returned))

        elif addr == 0x483:
          fields = decode_fca12(dat)
          for status_name in ("fca_usm", "fca_drv_set_state"):
            status_key = ("fca12_status", status_name, bus, returned)
            status = fields.get(status_name)
            if status_key in last_status and status != last_status[status_key]:
              tag(
                "fca12_status_change",
                mono_s,
                src,
                bus,
                returned,
                rejected,
                addr,
                dat,
                {"field": status_name, "old": last_status[status_key], "new": status},
                key=(*status_key, last_status[status_key], status),
              )
            last_status[status_key] = status

        elif addr == 0x421:
          fields = decode_scc12(dat)
          status_key = ("scc12_warn", bus, returned)
          status = fields.get("cf_vsm_warn_scc12")
          if status_key in last_status and status != last_status[status_key]:
            tag(
              "scc12_warn_change",
              mono_s,
              src,
              bus,
              returned,
              rejected,
              addr,
              dat,
              {"old": last_status[status_key], "new": status},
              key=(*status_key, last_status[status_key], status),
            )
          last_status[status_key] = status
          if active_scc12_actuation(fields) or fields.get("cf_vsm_warn_scc12"):
            tag("scc12_warning_fields", mono_s, src, bus, returned, rejected, addr, dat, fields, key=("scc12_warning_fields", bus, returned))

        elif addr == 0x2AB:
          fields = decode_escc_out(dat)
          for status_name in ("cf_vsm_warn_fca11", "cf_vsm_warn_scc12"):
            status_key = ("escc_out_status", status_name, bus, returned)
            status = fields.get(status_name)
            if status_key in last_status and status != last_status[status_key]:
              tag(
                "escc_output_status_change",
                mono_s,
                src,
                bus,
                returned,
                rejected,
                addr,
                dat,
                {"field": status_name, "old": last_status[status_key], "new": status},
                key=(*status_key, last_status[status_key], status),
              )
            last_status[status_key] = status
          if active_escc_warning_or_actuation(fields):
            tag("escc_output_warning_fields", mono_s, src, bus, returned, rejected, addr, dat, fields, key=("escc_output_warning_fields", bus, returned))

        if addr in SCC_ADDRS and bus == CAR_BUS and not returned and not rejected:
          last_physical_car_scc = mono_s

        if addr in SCC_ADDRS and bus == CAR_BUS and returned and (mono_s - last_physical_car_scc) <= 0.150:
          tag(
            "scc_forwarded_inside_block_window",
            mono_s,
            src,
            bus,
            returned,
            rejected,
            addr,
            dat,
            {"seconds_after_physical_car_scc": round(mono_s - last_physical_car_scc, 6)},
            key=("scc_forwarded_inside_block_window", addr),
          )

      if mono_s - last_health_time >= args.health_period:
        global_health, can_health = snapshot_health(panda)
        write_health_row(health_writer, start_mono_ns, global_health, can_health)
        health_f.flush()
        last_health_time = mono_s

        if prev_global_health is not None:
          changes = {}
          for key in HEALTH_EVENT_KEYS:
            old = prev_global_health.get(key)
            new = global_health.get(key)
            if old != new:
              changes[key] = {"old": old, "new": new}
          if changes:
            tag("panda_health_change", mono_s, "health", "", False, False, None, b"", changes, key=("panda_health_change", tuple(sorted(changes))))

          for bus in (CAR_BUS, RADAR_BUS):
            changes = {}
            for key in CAN_HEALTH_EVENT_KEYS:
              old = prev_can_health[bus].get(key)
              new = can_health[bus].get(key)
              if old != new:
                changes[key] = {"old": old, "new": new}
            if changes:
              tag("can_health_change", mono_s, "health", bus, False, False, None, b"", changes, key=("can_health_change", bus, tuple(sorted(changes))))

        prev_global_health = global_health
        prev_can_health = can_health

      if mono_s - last_status_print >= 1.0:
        raw_f.flush()
        status = " ".join(f"bus{bus}{'T' if returned else ''}{'R' if rejected else ''}:{count}" for (bus, returned, rejected), count in sorted(counts.items()))
        print(f"msgs {status} events:{sum(event_counts.values())}", end="\r")
        last_status_print = mono_s

  except KeyboardInterrupt:
    print("\nStopping capture.")
  finally:
    raw_f.close()
    events_f.close()
    health_f.close()

  print(f"Saved CAN log:    {capture_dir / 'can.csv'}")
  print(f"Saved event tags: {capture_dir / 'events.csv'}")
  print(f"Saved health log: {capture_dir / 'health.csv'}")
  return 0


if __name__ == "__main__":
  sys.exit(main())
