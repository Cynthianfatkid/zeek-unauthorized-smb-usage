# Unauthorized SMB Usage - Zeek Package

This Zeek package detects SMB/SMB2 connections to unauthorized IP addresses based on a configurable whitelist.

## 🚀 Features

- Detects lateral movement attempts via SMB.
- Alerts on SMB connections to IPs not in a trusted list.
- Works with both SMB1 and SMB2 sessions.

## 🛠 Configuration

Edit the allowed SMB server IPs in `main.zeek`:

```zeek
const smb_allowed_ips: set[addr] = {
    192.168.1.10,
    192.168.1.11
} &redef;
```

## 🧪 Usage

1. Install using ZKG (Zeek Package Manager).
2. Load the script via `@load yourgithub/unauthorized-smb-usage`.
3. Run Zeek on live traffic or PCAPs.
4. Watch `notice.log` for alerts like:

```
Unauthorized SMB access to 192.168.1.50 by user123
```

## 📄 License

MIT
