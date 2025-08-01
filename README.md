# Windows 11 PC Care Package

## Scope
This script is intended to automate much of the setup process of a new Windows 11 PC.

> [!Caution]
> **Use with caution**
> This script is untested as of 2025-08-01 and is a modification of a similar Windows 10 setup script which caused breaking changes under Windows 11.
> Run with the knowledge this may break your system without prior testing.

## Currently Planned Additions
- [ ] Test function of script
- [ ] Add standard application installs utilizing WinGet

---

## What This Script Does
🛡️ Administrative Elevation
- Checks for admin rights and relaunches with elevation if needed.

🧠 Registry & Profile Setup
- Loads and modifies the Default user hive to apply settings to future profiles.
- Defines RegSetUser function to adjust registry settings for current and default users.

🖥️ System Management
- Renames the computer based on user input.
- Creates/updates a local user named iscadmin, sets password, ensures it never expires.
- Disables automatic reboot on BSOD.

📁 File Explorer Settings
- Removes "- Shortcut" suffix from new shortcuts.
- Enables file extensions visibility and menu bar in Explorer.
- Sets Explorer launch view to “This PC”.

🔋 Power Settings
- Disables hibernation, standby/sleep on AC power, and Fast Boot.

🧹 System Cleanup & Debloat
- Disables “consumer features” and silent app installs.
- Removes most built-in apps for all users (preserving only essentials like Calculator, Photos, Paint, etc.).
- Disables:
	- Xbox DVR
 	- Featured software installs
	- Suggested apps
	- Spotlight content
	- Delivery Optimization
	- Advertising ID
	- Feedback prompts

🔐 Privacy & Telemetry Hardening
- Disables:
	- Telemetry
	- Diagnostics tracking services
	- SmartGlass
	- Device sync & history
	- Bing search
	- Implicit data collection (typing, inking)
	- CEIP (Customer Experience Improvement Program)
	- Application Compatibility tracking
	- UPNP device pairing
	- Advertising ID
	- Do Not Track is enabled for Microsoft Edge

🧰 Service Management
- Stops and disables:
	- DiagTrack, DmwApPushService, Xbox services, Distributed Link Tracking, WMPNetworkSvc

🌐 Remote Access
- Enables Remote Desktop and relevant firewall rules.
- Enforces user authentication for RDP.

🕒 Other System Configurations
- Sets system timezone to Eastern Standard Time (EST).
- Enables F8 Boot Menu (legacy boot options).
- Sets PowerShell script execution policy back to Undefined prior to exiting.

✅ Final Prompts and Reminders
- ASCII art outro with reminders to:
	- Run updates
	- Install LoB apps
	- Set startup/recovery options
	- Restart the computer
