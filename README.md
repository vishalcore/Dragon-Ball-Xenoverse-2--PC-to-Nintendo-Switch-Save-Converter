# Dragon Ball Xenoverse 2: PC to Nintendo Switch Save Converter

A fast, zero-dependency tool to transfer your **Dragon Ball Xenoverse 2** save file from PC (Steam) to a modded Nintendo Switch.

---

### What Gets Transferred:
- **Main Story Progression:** Continues right where you left off on PC (no restarting at Raditz).
- **Parallel Quests (PQs):** All cleared PQs, rankings (Z, S, A, etc.), and scores.
- **Sub-Quests & Side Content:** Expert Missions, Mentor friendship & progression, and Conton City exploration flags.
- **Your PC Character:** Brought over into **Slot 1** as your primary playable character with stats, skills, equipment, and level.
- **Switch Roster Preserved:** Existing Switch characters are automatically shifted to keep them safe from deletion.
- **Currencies Merged:** PC and Switch Zeni and TP Medals are added together.

---

## Prerequisites

1. **Computer:** Windows, macOS, or Linux with [Node.js](https://nodejs.org/) installed (any version 14 or newer).
2. **Nintendo Switch:** A modded Switch running Atmosphere with a save manager (**JKSV** or **Checkpoint**).

---

## Quick Step-by-Step Guide

### Step 1: Backup your Switch Save
1. On your Switch, launch **JKSV** or **Checkpoint** via the Homebrew Menu.
2. Select **Dragon Ball Xenoverse 2** and choose **New Backup** (e.g. name it `SwitchBackup`).
3. Connect your Switch SD card to your computer (or use DBI MTP responder / FTP).
4. Locate your backup:
   - **JKSV path:** `sdmc:/JKSV/Dragon Ball Xenoverse 2/SwitchBackup/savefile1.dat`
   - **Checkpoint path:** `sdmc:/switch/Checkpoint/saves/0x01007AD003F54000.../SwitchBackup/savefile1.dat`
5. Copy `savefile1.dat` to your computer.

### Step 2: Locate your PC Save
Find your PC Xenoverse 2 save (`dbxv2.sav`):
- **Steam Default Path:**
  `C:\Program Files (x86)\Steam\userdata\<YOUR_STEAM_ID>\323470\remote\DBXV2\dbxv2.sav`

---

### Step 3: Run the Conversion Command

Open your terminal (macOS/Linux) or Command Prompt / PowerShell (Windows) in the folder containing `convert.js`:

```bash
node convert.js --pc "/path/to/dbxv2.sav" --switch "/path/to/savefile1.dat"
```

#### Windows Example:
```cmd
node convert.js --pc "C:\Users\YourName\Documents\dbxv2.sav" --switch "D:\JKSV\savefile1.dat"
```

#### macOS / Linux Example:
```bash
./convert.js --pc "./pc save file/dbxv2.sav" --switch "./switch save file/savefile1.dat"
```

#### Output:
The tool will output the ready-to-use save at:
`./output/savefile1.dat` (Exact expected size: `722,944` bytes).

---

### Step 4: Restore on your Switch
1. Copy the new `output/savefile1.dat` file and overwrite the `savefile1.dat` in your SD card's backup folder (e.g. inside `sdmc:/JKSV/Dragon Ball Xenoverse 2/SwitchBackup/`).
2. Insert your SD card back into the Switch (or close MTP/FTP).
3. Open **JKSV** or **Checkpoint**, highlight your backup folder, and select **Restore**.
4. Boot into **Dragon Ball Xenoverse 2**. You will spawn directly in Conton City with your PC story progress, parallel quests, and character ready!

---

## Command Reference & Options

| Option | Shorthand | Description | Default |
| :--- | :--- | :--- | :--- |
| `--pc <path>` | `-p` | Path to your PC `dbxv2.sav` | *Required* |
| `--switch <path>` | `-s` | Path to your Switch `savefile1.dat` | *Required* |
| `--out <path>` | `-o` | Custom destination for the output save | `./output/savefile1.dat` |
| `--no-merge-money` | | Keeps original Switch Zeni and TP medals without adding PC currency | Off (merges by default) |
| `--help` | `-h` | Display usage instructions and examples | |
