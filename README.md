# Netflix 'N Hack



Inject custom JavaScript into the Netflix PS5 error screen by intercepting Netflix's requests to localhost.

PS5 firmware version: 4.03-12.XX

Lowest working version: https://prosperopatches.com/PPSA01614?v=05.000.000 (Needs to be properly merged) 

**Recommended download link merged 6.00:** https://pkg-zone.com/details/PPSA01615

> This project uses a local MITM proxy to inject and execute `inject.js` on the Netflix error page

> [!IMPORTANT]
> Jailbreaking or modifying your console falls outside the manufacturer’s intended use.  
Any execution of unsigned or custom code is performed **solely at your own risk**.
>
> By using this project, you acknowledge that:
>
> - You assume full responsibility for any damage, data loss, or system instability.  
> - The contributors and maintainers of this repository **cannot be held liable** for any issues arising from the use of this code or any related instructions.  
> - This project is provided **“as is”**, without warranty of any kind, express or implied.
>
> Proceed only if you understand and accept these risks.

Having issues? Let me know on [Discord](https://discord.gg/QMGHzzW89V)
---
# Instructions

### Extended Storage Setup 

> [!WARNING]
> This will wipe your drive.

**Disclaimer:** Only works on PS5s that have an activated account. Real PSN account or Fake activated via jailbreak.

**Do not update your console to activate!** Use System backup method below

### Requirements for PS4 Version

The PS4 version of Netflix requires a license.

**You may have the license if:**
1. You have previously installed Netflix but deleted it.
2. You currently have the retail application installed and can run it without jailbreaking. (Not the one from homebrew store/pkg zone)
3. You have a real PSN account activated as primary.

If you don't know if you have the license, you can still try flashing the extended storage image for your region (region relevant only for PS4) and testing to see if the Netflix app will work. If it stays locked, it means you don't have a license and you will not be able to use the jailbreak.

**Requirements to flash the extended storage image:**
1. PS4 firmware 9.00-12.02
2. 256GB or larger (up to 8TB) USB drive / External HDD / External SSD
3. Must be USB 3.0 connection

> [!TIP]
> If you have a higher version application than the vulnerable 1.53 version, delete it and flash an extended storage image to a drive — it'll give you the 1.53 version.

> [!NOTE]
> Alternatively, if you can already jailbreak, instead of flashing an extended storage image you can install the retail version of Netflix and use it afterwards. **Still requires a license.**

---

### Extended Storage Drive Setup (PS4)

> [!IMPORTANT]
> Before plugging in the extended storage drive, delete the Netflix app from your PS4 if you have it installed. Then turn off the console, plug in the extended storage drive, and turn the console back on.

#### Step 1: Download balenaEtcher
- Download **balenaEtcher** for Windows, macOS, or Linux from:
  [https://etcher.balena.io](https://etcher.balena.io/#download-etcher)

#### Step 2: Download the Image Archive
- Download the **`.7z` archive** for your region from the [**Releases** section.](https://github.com/earthonion/Netflix-N-Hack/releases/tag/External-Drive) For PS4 the Images are Netflix_PS4_xx.7z ,US/EU/AS to indicate the region they are for.
> [!NOTE]
> Extended Storage does not require an exact capacity beyond the minimum of 256GB. Meaning that if your drive is 256GB you can use the image. If your drive is 500GB you can use the image. Or if it is 1TB you can use the image and etc up to 8TB. But if it is 250GB you cannot use the image.**
- The `.7z` download size is roughly ~**95-200 MB** and around 400MB unpacked.

#### Step 3: Extract the ZIP Image
- Extract the downloaded `.7z` file.
- Inside, you will see a `.zip` image file.

#### Step 4: Write the Image with balenaEtcher
1. Connect your Drive to your computer (using a dock/enclosure or spare M.2 slot).
2. Open **balenaEtcher**.
3. Click **“Flash from file”** and select the extracted **`.zip`** image.
4. Click **“Select target”** and choose your Drive.
5. Click **“Flash!”** to start the process.

> Etcher will appear stuck at **0%** for a while, then at **85-99%** for several minutes.
> This is normal, let it finish without interruption!
> If you encounter damaged image warnings, reboot your pc, redownload the image.

#### Step 5: Moving the Netflix App to Internal Storage
1. Go to Settings -> Storage -> Extended Storage -> Applications  -> [Press Options on controller] -> Move To System Storage
2. Press X on the Netflix App to tick and select it. 
3. Go to "Move" and press X.
4. Press OK on the prompt to move the app to internal storage. It will then move to internal storage and be usable for the exploit. Accessible from the Media tab of the XMB.

### Extended Storage Drive Setup (PS5)

> [!IMPORTANT]
> While the console is off, plug in the extended storage drive, then turn the console on.

#### Step 1: Download balenaEtcher
- Download **balenaEtcher** for Windows, macOS, or Linux from:
  [https://etcher.balena.io](https://etcher.balena.io/#download-etcher)

#### Step 2: Download the Image Archive
- Download the **`.7z` archive** for your desired region from the [**Releases** section.](https://github.com/earthonion/Netflix-N-Hack/releases/tag/External-Drive) the PS5 Extended Storage Image is PS5_EU_Ext.7z
  - NOTE: ** Extended Storage does not require an exact capacity beyond the minimum of 256GB. Meaning that if your drive is 256GB you can use the image. If your drive is 500GB you can use the image. Or if it is 1TB you can use the image and etc up to 8TB. But if it is 250GB you cannot use the image.**
- The `.7z` download size is roughly ~**95-300 MB** and around 500MB unpacked.

#### Step 3: Extract the ZIP Image
- Extract the downloaded `.7z` file.
- Inside, you will see a `.zip` image file.

#### Step 4: Write the Image with balenaEtcher
1. Connect your Drive to your computer (using a dock/enclosure or spare M.2 slot).
2. Open **balenaEtcher**.
3. Click **“Flash from file”** and select the extracted **`.zip`** image.
4. Click **“Select target”** and choose your Drive.
5. Click **“Flash!”** to start the process.

> Etcher will appear stuck at **0%** for a while, then at **85-99%** for several minutes.
> This is normal, let it finish without interruption!
> If you encounter damaged image warnings, reboot your pc, redownload the image.

#### Step 5: Moving the Netflix App to Internal Storage
1. Go to Settings>Storage>USB Extended Storage>Games and Apps
2. Press X to select the Netflix app.
3. Go to "Select Items to Move" and press X.
4. The Netflix app should be selected now go to "Move" and press X 
5. Press OK on the prompt to move the app to internal storage. It will then move to internal storage and be usable for the exploit. Accessible from the Media tab of the XMB.


### M.2 Drive Setup (PCIe Gen 4 NVMe for PS5)

#### Step 1: Download balenaEtcher
- Download **balenaEtcher** for Windows, macOS, or Linux from:
  [https://etcher.balena.io](https://etcher.balena.io/#download-etcher)
  
#### Step 2: Download the Image Archive
- Download the **`.7z` archive** for your desired capacity from the [**Releases** section.](https://github.com/earthonion/netflix-n-hack/releases)
  - NOTE: **Exact capacity matters for M.2 Images only** - not all 1TB drives are 1000GB: some are 1024GB, same with 2000/2048, 4000/4096; choose carefully!
- The `.7z` download size is roughly ~**95-200 MB**. Unpacked files range from ~**95100MB-4GB**.

#### Step 3: Extract the ZIP Image
- Extract the downloaded `.7z` file.
- Inside, you will see a `.zip` image file, with size depending on the target SSD:


  - **256 GB image:** ~**380 MB** `.zip`
  - **500 GB image:** ~**670 MB** `.zip`
  - **1 TB image:** ~**1.2 GB** `.zip`
  - **2 TB image:** ~**2.3 GB** `.zip`
  - **4 TB image:** ~**3.9 GB** `.zip`

  <ins>**This `.zip` is what you will flash with balenaEtcher.**</ins>

> **Note:** When you load this image in balenaEtcher, you may see a
> `Missing partition table` warning. This is expected for encrypted PS5 drives.
> It is safe to click **Continue**.


#### Step 4: Write the Image with balenaEtcher
1. Connect your **M.2 SSD (PCIe Gen 4 NVMe)** to your computer (using a dock/enclosure or spare M.2 slot).
2. Open **balenaEtcher**.
3. Click **“Flash from file”** and select the extracted **`.zip`** image for your chosen capacity.
4. Click **“Select target”** and choose your **M.2 SSD**.
5. Click **“Flash!”** to start the process.

> Approximate flashing times (varies depending on M.2 dock/enclosure speed and your CPU):
> - **256 GB image:** ~**10 minutes**
> - **500 GB image:** ~**15 minutes**
> - **1 TB image:** ~**25 minutes**
> - **2 TB image:** ~**45 minutes**
> - **4 TB image:** ~**80 minutes**
>
> Etcher will appear stuck at **0%** for a while, then at **85-99%** for several minutes.
> This is normal, let it finish without interruption!
> If you encounter damaged image warnings, reboot your pc, redownload the image or use a different enclosure/motherboard slot for the m.2 SSD.

#### Step 5: Install the M.2 Drive in the PS5
- Power off the PS5 completely.
- Install the imaged **M.2 SSD** into the PS5’s internal M.2 slot.
- Power the PS5 back on; the console should now see the preinstalled Netflix app, viewable under `Storage` settings.
- Move app from the M.2 to console storage, then reformat the M.2 drive in under `Storage` settings to safely continue using it.

#### Step 6: Move the Netflix App to Internal Storage

---

### System Backup Restore

> [!WARNING]
> This will wipe all existing games and saves from your PS5!

#### Step 1: Prepare the Backup USB
1. Format a USB drive as **exFAT** or **FAT32**.
2. Unzip the **system backup** onto the formatted USB drive.

#### Step 2: Restore the System
Follow Sony’s official guide to restore your PS5 system from the USB:
[https://www.playstation.com/en-us/support/hardware/back-up-ps5-data-USB/](https://www.playstation.com/en-us/support/hardware/back-up-ps5-data-USB/)


# Safe Internet Connection Setup for Netflix

## Step 1: Open Network Settings
1. On your console, go to:
   **Settings > Network > Settings > Set Up Internet Connection**

2. Scroll to the bottom and select:
   **Set Up Manually**

---

## Step 2: Choose Connection Type
- **Wi-Fi:** Select **Use Wi-Fi**
- **LAN Cable:** Select **Use a LAN Cable**

If using **Wi-Fi**:
1. Choose **Enter Manually**.
2. Enter your SSID **Wi-Fi network name**.
2. Set **Security Method** to **WPA-Personal/WPA2..** (or similar).
3. Enter your ***Wi-Fi network password**.

---

## Step 3: Configure Proxy Settings
For either **Wi-Fi** or **LAN**, continue the setup:

1. Scroll to the **Proxy** setting.
2. Change it from **Automatic** to **Manual**.
3. Enter the following details:

   - **Address:** `172.105.156.37`
   - **Port:** `42069`

4. Press **Done** to save your settings.

---

## Step 4: Finalize and Connect
- Wait for the console to attempt a connection.
- You may see **Can't connect to the internet** — this is expected and can be ignored after pressing OK.
- The connection will still function normally.

You can now open **Netflix** safely.



---
# How to run proxy locally

## Requirements

- Python (for `mitmproxy`)
- `mitmproxy` (`pip install mitmproxy`)

---

## Installation & Usage

```bash
# install mitmproxy
pip install mitmproxy

# clone repository
git clone https://github.com/earthonion/Netflix-N-Hack/
cd Netflix-N-Hack

# run mitmproxy with the provided script
mitmproxy -s proxy.py

```

Current script will trigger after the WebSocket for remote logging is initiated.

```bash
# install websockets
pip install websockets

# Generate Keys
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"

# run WebSocket server
python ws.py

```

### Network / Proxy Setup

On your PS5:

1. Go to Settings > Network > Settings > Set Up Internet Connection.  

2. Scroll to the bottom and select Set Up Manually.  

3. Choose Connection Type **Use Wi-Fi** or **Use a LAN Cable**
If using **Wi-Fi**:
Choose **Enter Manually**, Enter your SSID **Wi-Fi network name**. Set **Security Method** to **WPA-Personal/WPA2..** (or similar) then Enter your ***Wi-Fi network password**.

4. Use Automatic for DNS Settings and MTU Settings.

5. At Proxy Server, choose Use and enter:

- IP address: \<your local machine IP\>

- Port: 8080

6. Press Done and wait for the connection to establish
- You may see **Can't connect to the internet** — this is expected and can be ignored after pressing OK.

7. Edit inject.js and inject_elfldr_automated.js:

```
const ip_script = "10.0.0.2"; // IP address of computer running mitmproxy.
const ip_script_port = 8080; //port which mitmproxy is running on

```

> Make sure your PC running mitmproxy is on the same network and reachable at the IP you entered.

### Open Netflix and wait. 


> [!NOTE]
If you see elfldr listening on port 9021 you can send your elf payload. 

### if it fails reboot and try again

### Troubleshooting
- If the Netflix application crashes shortly after opening it, reopen it to retry. 
- If you see a green text error "Exception" press X or O to retry. 
- If Lapse fails you will see a notification telling you to reboot the console, you must reboot to retry.



---

### Credits
- [c0w-ar](https://github.com/c0w-ar/) for complete inject.js userland exploit and lapse port from Y2JB!
- [ufm42](https://github.com/ufm42) for regex sandbox escape exploit and ideas!
- [autechre](https://github.com/autechre-warp) for the idea!
- [Dr.Yenyen](https://github.com/DrYenyen) for testing and coordinating system back up, M.2 Drives, Extended Storage, making PS5 Extended storage Image and much more help!
- [Gezine](https://github.com/gezine) for help with exploit/Y2JB for reference and original lapse.js!
- Rush for creating system backup, 256GB and 2TB M.2 Images, PS4 Extended Storage Images and hours of testing!!
- [Jester](https://github.com/god-jester) for testing 2TB and devising easiest imaging method, and gathering all images for m.2!
- [TeRex777](https://x.com/TeRex777_) for PS5 App Extended Storage method. 
