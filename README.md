# ACE privacy checker for NIKKE

Shows what NIKKE's crash reporter (Tencent CrashSight) and the ACE anti-cheat stored on your Windows PC and uploaded from it: which of your accounts were named in uploaded reports, what device details went with them, and whether any verdict, cheat or ban wording exists anywhere. It reads and copies. It never changes, stops or removes anything, and it does not touch the game process.

The background, and what the data means, is in [What NIKKE's PC client sends home](https://yap.whykusanagi.xyz/p/2026-10-02-nikke-ace-anti-cheat). Read that first if you want to know why this exists.

## Usage

1. Close NIKKE and the NIKKE launcher.
2. Download the zip from the latest release and extract it (right-click the zip, "Extract All..."). Do not run anything from inside the zip.
3. Double-click `Run-TelemetryCheck.cmd`.
   If Windows shows "Windows protected your PC", click "More info", then "Run anyway". No administrator rights are needed.
4. Wait one to three minutes. Do not click inside the black window while it works; if it looks frozen, press Esc.
5. The report opens in Notepad when the run finishes. It is also saved in a folder called `ACE-Telemetry-Output` next to the `.cmd` file.

Running `Check-AceTelemetry.ps1` directly does the same thing. `-Destination <folder>` picks another output folder and `-NoZip` skips the zip.

## What you get

Inside `ACE-Telemetry-Output`:

| File | Contents |
| --- | --- |
| `<PC>-<date>-SUMMARY.txt` | The report: uploaded reports, accounts named in them, verdict scan, other metadata that left the PC |
| `<PC>-<date>\` | Everything that was collected, so you can inspect it yourself |
| `<PC>-<date>\crashsight\decoded-records.csv` | One row per crash report: account, scene, error, device fields, upload status |
| `<PC>-<date>\crashsight\accounts-uploaded.csv` | The accounts named in reports that were uploaded |
| `<PC>-<date>\crashsight\fields-seen.txt` | Every field the game attaches to a report |
| `<PC>-<date>\crashsight\verdict-scan.txt` | Every line that mentions verdict, cheat, ban, kick and similar words, and where it came from |
| `<PC>-<date>.zip` | The same folder zipped, usually 2 to 10 MB |

## Data precautions

The output contains your player information. Read the summary before you share anything, and share it only with people you trust.

In the output:

- The crash reports themselves. They contain the NIKKE account IDs and nicknames used on this PC, your PC's network MAC address, CPU, GPU and Windows model names, the game scene you were in and the error text.
- The game's `Player.log`. It records ACE start-up and each login. File paths in it can contain your Windows user name.
- Crash-reporter session logs, ACE version and registry facts, the encrypted Level Infinite analytics queue files, the launcher database (one table per account), the names of your per-account cache files, the lines of Easy Anti-Cheat logs that mention ACE, and Windows event entries about ACE and NIKKE crashes.

Not collected: passwords or login tokens, browser data, game assets, full Windows event logs, serial numbers, network, DNS or process listings, installed programs, documents or any personal files.

If something in the folder is a problem for you, delete it and zip the folder yourself instead of using the ready-made zip. Delete the whole output folder once you are done with it. Nothing leaves your PC unless you send it somewhere.

## Known limitations

- If NIKKE is installed more than once (for example the standard PC client and the Google Play Games version), the check reads the first `nikke.exe` it finds.
- The report shows what is on disk now. Reports the game already deleted, and anything sent through channels that leave no file behind, are not visible to it.
- Windows 10 and 11 with the built-in PowerShell 5.1. The decoder compiles two small C# helpers at run time; if that fails, the raw records are still collected and the summary says the decoder was unavailable.

## Liability

You run this on your own PC at your own risk. The script is plain text and you can read every line of it in Notepad before running it. It reads files and registry values and writes its output to one folder; it is not a cheat, does not modify the game or the anti-cheat, and the author makes no claim about how the game's vendor treats PCs on which it was run. The findings in the report describe files found on your PC; interpretation is up to you. The software is provided as is, without warranty of any kind, as stated in the license.

## License

MIT. See [LICENSE](LICENSE).
