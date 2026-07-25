#!/usr/bin/env bash
set -euo pipefail

GUI_OPS=/opt/nms-collector/nms-gui-operations.sh

if [[ "$#" -eq 1 && "$1" == "--status" ]]; then
  exec "${GUI_OPS}" tinysa-status
fi

if [[ "$#" -ne 12 ]]; then
  echo "usage: $0 MODEL DEVICE BAND START_HZ STOP_HZ POINTS INTERVAL ANTENNA_PROFILE CALIBRATION_STATE AGGREGATION SWEEP_REPETITIONS ENABLED" >&2
  exit 2
fi

exec "${GUI_OPS}" tinysa-config "$@"
