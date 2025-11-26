# Netflix N Hack for PS4 (coming soon)

> [!NOTE]
> The PS4 version requires very specific circumstances to work. Workarounds are included below.

## Compatibility

Before proceeding, ensure the following:

1. **Netflix (with license) installed on your PS4 below the latest version**
    - If you have an existing jailbreak, simply install the vulnerable version for your region [EU](https://orbispatches.com/CUSA00127?v=01.53)  [US](https://orbispatches.com/CUSA00129?v=01.53) [JP](https://orbispatches.com/CUSA02988?v=01.53)
    - This is useful if you can’t afford BD-JB or are stuck using PPPwn.
    - If you are on the latest firmware, you *can* downgrade Netflix via MITM by downloading from PSN.  
      You **cannot jailbreak**, but you will be prepared if a new kernel exploit releases.

2. **PS4 Firmware version must be between 9.00 and 12.02** (required for the Lapse exploit)

---

## Downgrading Netflix

### Prerequisites
- Python
- mitmproxy
- Internet access

### Install & Run Downgrade Proxy
```bash
# Install mitmproxy
pip install mitmproxy

# Start the downgrade proxy
mitmproxy -s downgrader.py --ssl-insecure
```
**Console Instructions**

Before continuing. set up your Internet connection and when it asks for proxy, click use, then input the local IP of the computer running mitmproxy 

On your PS4:

1. Go to Netflix **on the home screen**


2. Press **Options** on your controller 


3. Select **Check for Updates**



It will appear to download the newest version, but after install it should downgrade to **1.53**.


---

## Exploit

### Start MITM Proxy

```bash
mitmproxy -s proxy.py
```

Then simply open Netflix on your PS4.
(Exploit initialization takes ~30 seconds.)

This will spawn the Remote JS payload server.
Send payloads/lapse_ps4.js via netcat or any equivalent tool.

Important Notes

> [!NOTE]
> You will not see any output while the exploit is executing.
If the app crashes or the PS4 kernel panics, restart the console and try again.



Once complete, the exploit spawns a bin loader on port 9021.

Now you can send any HEN payload of your choice.


---

If you run into issues, feel free to message me on Discord!
