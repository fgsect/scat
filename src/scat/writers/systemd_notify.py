import subprocess

def systemd_notify_watchdog_alive():
    subprocess.run(["systemd-notify", "WATCHDOG=1"], check=True)
