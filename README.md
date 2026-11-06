# BMW NBT Evo HDD ATA Security Unlock

Standalone ATA security unlock tool for BMW NBT Evo hard drives.

---

## Disclaimer and Legal Notice

**READ BEFORE USING. BY DOWNLOADING, CLONING, OR USING ANY PART OF THIS REPOSITORY, YOU AGREE TO THE FOLLOWING TERMS IN FULL.**

This repository and all of its contents are provided **strictly for educational and informational purposes only**.

### Intended Use

This tool is intended exclusively for use by individuals who:
- **Own** the BMW NBT Evo head unit and hard drive they are attempting to unlock
- Are performing **personal hardware maintenance, data recovery, or repair** on their own vehicle
- Are acting in full compliance with the laws of their jurisdiction

### No Liability

The author(s) of this project accept **zero liability** for any damages, losses, legal consequences, or adverse outcomes arising from the use or misuse of this tool. No warranties are made regarding accuracy, safety, or fitness for purpose. **You are solely responsible for ensuring your use is lawful.**

### Prohibited Uses

You **must not** use this tool to:
- Unlock hardware you do not own or are not authorised to service
- Extract or distribute proprietary software or firmware belonging to BMW AG or any other rights holder
- Facilitate theft, fraud, or any illegal activity

### Reverse Engineering Notice

The password derivation algorithm was determined through reverse engineering solely for **interoperability** with researcher-owned hardware, a recognised lawful purpose in many jurisdictions (EU Directive 2009/24/EC Article 6; US DMCA §1201(f)). No proprietary code is reproduced here.

The author(s) reserve the right to remove or modify this repository at any time without notice.

---

## Background

The BMW NBT Evo head unit ships with a SATA hard drive locked using the **ATA Security feature set** (`SECURITY UNLOCK`, command `0xF2`). When the drive is removed and connected to a PC, all read/write commands are rejected until it is unlocked.

The ATA password is derived at boot from three hardware identifiers stored in the head unit's adjustblock:

| Field | Adjustblock key |
|---|---|
| Ethernet MAC address | `E2P.Networking.Eth0MacAddr` |
| Bluetooth MAC address | `E2P.Networking.Bt0Addr` |
| NBT unit serial number | `E2P.ProdLogistic.SerialNo` |

---

## Password Derivation Algorithm

> **Note:** The older NBT (non-Evo) unit uses a different, simpler algorithm. This does **not** apply there.

```
1. Hex-decode ETH_MAC  → 6 raw bytes
2. Hex-decode BT_MAC   → 6 raw bytes
3. Hex-decode SNR_HEX  → n raw bytes  (typically 10)
4. Concatenate: raw_eth + raw_bt + raw_snr
5. MD5 hash the concatenated bytes → 16 bytes
6. Base64-encode the first 15 of those 16 bytes → 20 ASCII characters
7. Write those 20 characters at offset 2 in the 512-byte ATA security buffer
8. Issue ATA SECURITY UNLOCK (0xF2) via SCSI/ATA Translation (SAT)
```

The resulting 20-character string is the ATA password.

---

## Getting Your Values

Read the required adjustblock values via SSH:

```bash
sysetadjread --get=E2P.Networking.Eth0MacAddr
sysetadjread --get=E2P.Networking.Bt0Addr
sysetadjread --get=E2P.ProdLogistic.SerialNo
```

> **Important:** `E2P.ProdLogistic.SerialNo` returns a **hex-encoded** string (e.g. `00303132333435363738`), not the human-readable serial on the unit's sticker. Use the raw hex value directly.

---

## Usage

Run the GUI:

```bash
sudo python3 nbt_unlock.py
```

Enter your ETH MAC, BT MAC, and Serial Number into the tool. The derived password will be displayed and the unlock can be issued directly from the interface.

The unlock is **temporary** — it resets on power cycle. To permanently remove the ATA password:

```bash
sudo hdparm --security-disable "<password>" /dev/sdX
# The tool displays the exact command after a successful unlock
```

---

## Requirements

- Linux
- Python 3
- `hdparm`
- Drive connected via **SATA** (not USB — ATA passthrough requires direct SATA)
- Drive must **not** be in `frozen` state (cold boot the PC with the drive connected if it is)

---

## Warnings

### Security Attempt Counter
The ATA security spec limits the number of failed unlock attempts before further attempts are rejected until the next power cycle. **Do not guess your values.** Retrieve them from the head unit first.

### Risk of Data Loss / Brick

> **WARNING: Issuing incorrect ATA security commands, SSHing into the head unit carelessly, or using the wrong flags with drive management tools carries a real risk of permanent data loss or an unrecoverable (bricked) head unit.**

Key risks:
- **Wrong SSH commands** on the head unit can corrupt the NAND filesystem or adjustblock — potentially unrecoverable without a full factory reflash
- **`hdparm --security-erase`** will **permanently and irrecoverably destroy all data** on the drive — do not confuse this with `--security-disable` or `--security-unlock`
- **Exceeding the unlock attempt counter** puts the drive in a frozen security state until power-cycled

**Read every command before running it. If you are unsure, stop.**

### Reinstalling the Drive in the Car

If you permanently remove the ATA password and then reinstall the drive, the head unit may log errors or behave unexpectedly depending on firmware version. To re-lock the drive before reinstalling:

```bash
# Unlock first (if currently locked)
sudo python3 nbt_unlock.py

# Re-apply the password
sudo hdparm --security-set-pass "<password>" /dev/sdX

# Confirm locked state
sudo hdparm -I /dev/sdX | grep -A 6 "Security:"
```

---

## Tested On

- **Vehicle**: 2016 BMW M235i
- **Head unit**: BMW NBT Evo (HU_NBT2), iStep 18-03 (ID5/6)
- **Drive**: HGST HEJ423220H9E300 (186GB)
- **Host OS**: Linux 6.17, Python 3.12



