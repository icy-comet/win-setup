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
Sr. | Function | Undo Possibility
---|---|---
1 | Create a Restore Point | —
2 | Install Custom Software | ❌
3 | Remove Bloatware | ❌
4 | Disable Unnecessary Scheduled Tasks | ✔️
5 | Disable Data Collection | ✔️
6 | Disable Wifi Sense | ✔️
7 | Disable User Activity History | ✔️
8 | Hide Tasks View button in Taskbar | ✔️
9 | Hide Meet Now button in Taskbar | ✔️
10 | Hide News And Interests in Taskbar | ✔️
11 | Hide Search Button/Box in Taskbar | ✔️
12 | Disable Collapsible Tray in Taskbar | ✔️
13 | Stop Edge from taking over as Default PDF Viewer | ✔️
14 | Disable Autorun | ✔️
15 | Disable Windows Search Indexing | ✔️
16 | Enable NTFS Long Paths (over 260 characters) | ✔️
17 | Disable searching for apps in Store for unknown extensions | ✔️
18 | Hide "Recently Added" list from Start Menu | ✔️
19 | Disable Windows App Suggestions | ✔️
20 | Disable Web Search In Start Menu | ✔️
21 | Disable Nav. Pane Expand (Explorer) | ✔️
22 | Show File Extensions in Explorer | ✔️
23 | Set 12-Hour Time Format | —
24 | Change Time Zone to IST | —
25 | Change PC Name | —
26 | Set Control Panel's view to Large Icons | —
27 | Optimize C Drive | —

## Optionals
Sr. | Function | Undo Possibility
---|---|---
28 | Change Explorer's Default Location to "This PC" | ✔️
29 | Hide 3D Objects from Explorer | ✔️
30 | Set BIOS Time to UTC | ✔️
31 | Disable Fast Startup | ✔️
32 | Show Hidden Files in Explorer | ✔️
33 | NetworkingOptimizations | ✔️
34 | Disable F1 Help Key (Explorer & Desktop) | ✔️
35 | Unhide Desktop Icons -- User's Home Folder, This PC & Control Panel | ✔️
36 | Disable Firewall | ✔️

Note: I haven't touched most of Cortana to preserve Windows functions that most might expect to "just" work.

# Credits
- [Disassembler0's Initial Setup Script](https://github.com/Disassembler0/Win10-Initial-Setup-Script/)
- [Sycnex's Debloat Script](https://github.com/Sycnex/Windows10Debloater/)