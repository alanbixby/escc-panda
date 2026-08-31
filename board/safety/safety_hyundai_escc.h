#pragma once

#include "drivers/can_common_declarations.h"

#define DEVNULL_BUS (-1)
#define CAR_BUS 0
#define RADAR_BUS 2
// Backstop so CAR->RADAR forwarding can't exhaust tx3_q if the spur drains slowly.
#define RADAR_TX_QUEUE_MIN_SLOTS 50U
// The radar broadcasts SCC11/SCC12/SCC14/FCA11 at 50Hz whenever it is awake, so
// 200ms of bus-2 silence means the spur has no ACKing node. Forwarding into a
// dead spur pins the TX FIFO and churns the error-passive reset path.
#define RADAR_LINK_TIMEOUT_US 200000U
// While the link is down, still let one car frame per second through as a wake
// probe, in case the radar needs inbound bus activity before it starts talking.
#define RADAR_PROBE_INTERVAL_US 1000000U

bool scc_block_allowed = false;
bool sunnypilot_seen = false;
uint32_t sunnypilot_detected_last = 0;
uint32_t escc_radar_last_seen = 0;
uint32_t escc_probe_last = 0;
bool escc_radar_seen = false;
bool escc_radar_link_active = false;

// Initialize bytes to send to 2AB
ESCC_Msg escc = {0};

#ifdef ESCC_DIAG
typedef struct {
  uint32_t car_to_radar_forwarded;
  uint32_t radar_to_car_forwarded;
  uint32_t scc_blocked_car_to_radar;
  uint32_t scc_blocked_radar_to_car;
  uint32_t queue_pressure_drops;
  uint32_t canfd_frames_dropped;
  uint32_t non_scc_car_to_radar_frames;
  uint32_t fca11_fail_frames_bus2;
} ESCC_DiagCounters;

ESCC_DiagCounters escc_diag_counters = {0};

static void escc_diag_reset(void) {
  escc_diag_counters = (ESCC_DiagCounters){0};
}
#endif

static safety_config escc_init(uint16_t param) {
  scc_block_allowed = false;
  sunnypilot_seen = false;
  sunnypilot_detected_last = 0U;
  escc_radar_last_seen = 0U;
  escc_probe_last = 0U;
  escc_radar_seen = false;
  escc_radar_link_active = false;
#ifdef ESCC_DIAG
  escc_diag_reset();
#endif
  // Reuse alloutput controls setup; ESCC forwarding does not read alloutput_passthrough.
  return alloutput_init(param);
}

static void escc_rx_hook(const CANPacket_t* to_push) {
  const int bus = GET_BUS(to_push);
  const int addr = GET_ADDR(to_push);

  if (bus == RADAR_BUS) {
    escc_radar_last_seen = MICROSECOND_TIMER->CNT;
    escc_radar_seen = true;
  }

  const int is_scc_msg = addr == 0x420 || addr == 0x421 || addr == 0x50A || addr == 0x389;
  const int is_fca_msg = addr == 0x38D || addr == 0x483;
#ifdef DEBUG
  print("escc_rx_hook: "); putui(bus); print(" - "); puth4(addr); print(" is_scc_msg: "); print(is_scc_msg?"yes":"no"); print(" is_fca_msg: "); print(is_fca_msg?"yes":"no"); print("\n");
#endif

  if (bus == RADAR_BUS && (is_scc_msg || is_fca_msg)) {
    switch (addr) {
      // This messsage is blocked if scc_block_allowed is true, and ESCC is updated with the data and sent to sunnypilot
      case 0x420: // SCC11: Forward radar points to sunnypilot
        escc.obj_valid = (GET_BYTE(to_push, 2) & 0x1U);
        escc.acc_objstatus = ((GET_BYTE(to_push, 2) >> 6) & 0x3U);
        escc.acc_obj_lat_pos_1 = GET_BYTE(to_push, 3);
        escc.acc_obj_lat_pos_2 = (GET_BYTE(to_push, 4) & 0x1U);
        escc.acc_obj_dist_1 = ((GET_BYTE(to_push, 4) >> 1) & 0x7FU);
        escc.acc_obj_dist_2 = (GET_BYTE(to_push, 5) & 0xFU);
        escc.acc_obj_rel_spd_1 = ((GET_BYTE(to_push, 5) >> 4) & 0xFU);
        escc.acc_obj_rel_spd_2 = GET_BYTE(to_push, 6);
        send_escc_msg(&escc, CAR_BUS);
        break;

      // This messsage is blocked if scc_block_allowed is true, and ESCC is updated with the data and sent to sunnypilot
      case 0x421: // SCC12: Detect AEB, get the data and write it on the next ESCC msg to sunnypilot.
        escc.aeb_cmd_act = GET_BYTE(to_push, 6) >> 6 & 1U;
        escc.cf_vsm_warn_scc12 = GET_BYTE(to_push, 0) >> 4 & 0x3U;
        escc.cf_vsm_deccmdact_scc12 = GET_BYTE(to_push, 0) >> 1 & 1U;
        escc.cr_vsm_deccmd_scc12 = GET_BYTE(to_push, 2);
        break;

      // This message is not blocked, and is sent straight to the car.
      case 0x38D: // FCA11: Detect AEB, get the data and write it on the next ESCC msg to sunnypilot
        escc.fca_cmd_act = GET_BYTE(to_push, 2) >> 4 & 1U;
        escc.cf_vsm_warn_fca11 = GET_BYTE(to_push, 0) >> 3 & 0x3U;
        escc.cf_vsm_deccmdact_fca11 = GET_BYTE(to_push, 3) >> 7 & 1U;
        escc.cr_vsm_deccmd_fca11 = GET_BYTE(to_push, 1);
#ifdef ESCC_DIAG
        if ((GET_LEN(to_push) > 4U) && ((GET_BYTE(to_push, 4) & 0x7U) != 0U)) {
          escc_diag_counters.fca11_fail_frames_bus2 += 1U;
        }
#endif
        break;

      default: ;
    }
  }
}

static bool escc_tx_hook(const CANPacket_t* to_send) {
#ifdef DEBUG
  const int target_bus = GET_BUS(to_send);
  const int addr = GET_ADDR(to_send);
  print("escc_tx_hook: "); putui(target_bus); print(" - "); puth4(addr); print("\n");
  #else
  UNUSED(to_send);
  #endif
  return true;
}

static int escc_fwd_hook(const int bus_src, const int addr) {
#ifdef DEBUG
  print("escc_fwd_hook: "); putui(bus_src); print(" - "); puth4(addr); print(" scc_block_allowed: "); print(scc_block_allowed?"yes":"no" ); print("\n");
#endif
  // SCC messages are SCC11 (0x420), SCC12 (0x421), SCC13 (0x50A), SCC14 (0x389)
  const int is_scc_msg = addr == 0x420 || addr == 0x421 || addr == 0x50A || addr == 0x389;

  const uint32_t ts = MICROSECOND_TIMER->CNT;

  // Update the last detected timestamp if an SCC message is from CAR_BUS
  if (bus_src == CAR_BUS && is_scc_msg) {
    sunnypilot_seen = true;
    sunnypilot_detected_last = ts;
  }

  // Latch expiry so a 32-bit timer alias ~71.6min later can't re-block
  if (sunnypilot_seen && (get_ts_elapsed(ts, sunnypilot_detected_last) > 150000U)) {
    sunnypilot_seen = false;
  }
  scc_block_allowed = sunnypilot_seen;

  // Track radar liveness here too: the fwd hook runs before the rx hook for a
  // given frame, so this opens the link on the radar's own first frame
  if (bus_src == RADAR_BUS) {
    escc_radar_seen = true;
    escc_radar_last_seen = ts;
  }
  // Latch expiry (timer-alias immunity, same as above)
  if (escc_radar_seen && (get_ts_elapsed(ts, escc_radar_last_seen) > RADAR_LINK_TIMEOUT_US)) {
    escc_radar_seen = false;
  }
  escc_radar_link_active = escc_radar_seen;

  int bus_dst = DEVNULL_BUS;
  if (bus_src == CAR_BUS) {
    const bool radar_queue_has_space = can_slots_empty(can_queues[RADAR_BUS]) >= RADAR_TX_QUEUE_MIN_SLOTS;
    // Diagnostic range always passes: UDS sessions can legitimately pause the
    // radar's broadcasts (comm control), and the tool's requests must get through
    const bool is_diag_addr = (addr >= 0x700) && (addr <= 0x7FF);
    bool link_pass = escc_radar_link_active || is_diag_addr;
    if (!link_pass && (get_ts_elapsed(ts, escc_probe_last) >= RADAR_PROBE_INTERVAL_US)) {
      escc_probe_last = ts;
      link_pass = true;
    }
    bus_dst = (link_pass && radar_queue_has_space) ? RADAR_BUS : DEVNULL_BUS;
#ifdef ESCC_DIAG
    if (link_pass && !radar_queue_has_space) {
      escc_diag_counters.queue_pressure_drops += 1U;
    }
#endif
  } else if (bus_src == RADAR_BUS) {
    bus_dst = CAR_BUS;
  } else {
    // ESCC only bridges the car bus and isolated radar spur.
  }

  // If we are allowed to block, and this is an scc msg coming from radar (or somehow we are sending it TO the radar) we block
  if (scc_block_allowed && is_scc_msg && (bus_src == RADAR_BUS || bus_dst == RADAR_BUS)) {
#ifdef ESCC_DIAG
    if (bus_src == CAR_BUS) {
      escc_diag_counters.scc_blocked_car_to_radar += 1U;
    } else if (bus_src == RADAR_BUS) {
      escc_diag_counters.scc_blocked_radar_to_car += 1U;
    } else {
    }
#endif
    bus_dst = DEVNULL_BUS;
  }

#ifdef ESCC_DIAG
  if ((bus_src == CAR_BUS) && (bus_dst == RADAR_BUS)) {
    escc_diag_counters.car_to_radar_forwarded += 1U;
    if (!is_scc_msg) {
      escc_diag_counters.non_scc_car_to_radar_frames += 1U;
    }
  } else if ((bus_src == RADAR_BUS) && (bus_dst == CAR_BUS)) {
    escc_diag_counters.radar_to_car_forwarded += 1U;
  } else {
  }
#endif

  return bus_dst;
}

const safety_hooks hyundai_escc_hooks = {
  .init = escc_init,
  .rx = escc_rx_hook,
  .tx = escc_tx_hook,
  .fwd = escc_fwd_hook,
  .get_counter = hyundai_get_counter,
  .get_checksum = hyundai_get_checksum,
  .compute_checksum = hyundai_compute_checksum,
};
