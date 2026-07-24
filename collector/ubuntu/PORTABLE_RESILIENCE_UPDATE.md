# Portable Collector Resilience Update

Use this update after moving an Ubuntu field collector to another customer network.

It backs up the installed collector, clears static private/public IP values, restores the NetworkManager dispatcher, enables boot-time collector startup, and restarts the reporting services. It does not add VPN credentials or change collector tokens.

Run from the extracted package:

```bash
sudo bash apply-collector-portable-resilience-update.sh
```

Verify:

```bash
systemctl is-active nms-collector-heartbeat.timer
systemctl is-active nms-collector-diagnostic-worker.service
systemctl is-active nms-collector-edge-analysis.timer
systemctl is-enabled nms-collector-autostart.service
```

The next heartbeat reports the active route interface, the current private CIDR, gateway, and the centrally observed public IP. VPN status is optional remote-management telemetry and does not block HTTPS collection.
