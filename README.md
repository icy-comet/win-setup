<pre align="center">
  __  ____  _ ____    _  _  __  __ _       ____  ____  ____  _  _  ____
 / _\(_  _)(// ___)  / )( \(  )(  ( \ ___ / ___)(  __)(_  _)/ )( \(  _ \
/    \ )(    \___ \  \ /\ / )( /    /(___)\___ \ ) _)   )(  ) \/ ( ) __/
\_/\_/(__)   (____/  (_/\_)(__)\_)__)     (____/(____) (__) \____/(__)
</pre>

> A Windows setup script I maintain for a local client.

Feel free to customize and use it yourself.

# How to use?
- Edit the `setup_prefs.txt` template and mention all the function serials (from the tables below) to execute and undo on lines 7 and 11 respectively separated with a comma. Mention the action to take on line 3 -- `Undo` or `Setup`
- Edit `setup_apps.txt` to include winget IDs of the apps to be installed.
- Run `winget search <app-name>` to get the winget ID.
- You can also find the script's log file on your Desktop.

# Run
Open Powershell As Admin and enter:
```
iex ((New-Object System.Net.WebClient).DownloadString('https://git.io/JDcs6'))
```

# Reference
## Essentials
Sr. | Function | One-Click Restore?
---|---|---
1 | Install Custom Software | ❌
2 | Remove Bloatware | ❌
3 | Disable Unnecessary Scheduled Tasks | ✔️
4 | Disable Data Collection | ✔️
5 | Disable Wifi Sense | ✔️
6 | Disable User Activity History | ✔️
7 | Hide Tasks View button in Taskbar | ✔️
8 | Hide Meet Now button in Taskbar | ✔️
9 | Hide News And Interests in Taskbar | ✔️
10 | Hide Search Button/Box in Taskbar | ✔️
11 | Disable Collapsible Tray in Taskbar | ✔️
12 | Stop Edge from taking over as Default PDF Viewer | ✔️
13 | Disable Autorun | ✔️
14 | Disable Windows Search Indexing | ✔️
15 | Enable NTFS Long Paths (over 260 characters) | ✔️
16 | Disable searching for apps in Store for unknown extensions | ✔️
17 | Hide "Recently Added" list from Start Menu | ✔️
18 | Disable Windows App Suggestions | ✔️
19 | Disable Web Search In Start Menu | ✔️
20 | Disable Nav. Pane Expand (Explorer) | ✔️
21 | Show File Extensions in Explorer | ✔️
22 | Set 12-Hour Time Format & change TimeZone | —
23 | Change PC Name | —
24 | Set Control Panel's view to Large Icons | —
25 | Optimize C Drive | —
26 | Create a Restore Point | —

## Optionals
Sr. | Function | One-Click Restore?
---|---|---
27 | Change Explorer's Default Location to "This PC" | ✔️
28 | Hide 3D Objects from Explorer | ✔️
29 | Set BIOS Time to UTC | ✔️
30 | Disable Fast Startup | ✔️
31 | Show Hidden Files in Explorer | ✔️
32 | NetworkingOptimizations | ✔️
33 | Disable F1 Help Key (Explorer & Desktop) | ✔️
34 | Unhide Desktop Icons -- User's Home Folder, This PC & Control Panel | ✔️
35 | Disable Firewall | ✔️

Note: I haven't touched most of Cortana to preserve Windows functions that most might expect to "just" work.

# Credits
- [Disassembler0's Initial Setup Script](https://github.com/Disassembler0/Win10-Initial-Setup-Script/)
- [Sycnex's Debloat Script](https://github.com/Sycnex/Windows10Debloater/)