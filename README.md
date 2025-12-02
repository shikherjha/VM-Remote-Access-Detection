# VM & Remote Access Detection System

**Status: Work in Progress** - Just the basic skeleton for now. Adding new detection methods as I research them.

A Windows-based detection tool that identifies virtual machines and remote access sessions. This started as a research project to understand how people might cheat during online tests and what technical traces they leave behind.

## What This Does

Detects:
- Virtual machines (VMware, VirtualBox, Hyper-V, etc.)
- Remote desktop connections (RDP, TeamViewer, AnyDesk, VNC)
- Other remote access tools that might be used during online exams

## What's Currently Working

### VM Detection
- **Registry checks** - Looks for VM-specific registry entries
- **File system scanning** - Checks if VM driver files exist (like vboxmouse.sys, vmhgfs.sys)
- **Process detection** - Scans for running VM processes (vmtoolsd.exe, vboxservice.exe, etc.)

### Remote Access Detection
- **RDP detection** - Checks if someone's connected via Remote Desktop
- **Remote software** - Looks for TeamViewer, AnyDesk, VNC and similar tools running

These methods are pretty basic and can be evaded easily. That's why I'm researching better techniques.

## Project Structure (for now)

```
VMDetectionSystem/
├── VMDetectionSystem.cpp    # Main code
└── README.md                # You're reading it

Coming soon:
├── docs/                    # Research notes and findings
├── tests/                   # Test cases for different VMs
└── [more as I build it]
```

## Building and Running

### You'll Need
- Visual Studio 2019 or newer (Community edition works fine)
- Windows 7 or later
- Admin rights to run it (needs access to registry and process list)

### Build Steps
1. Clone this repo
2. Open `VMDetectionSystem.sln` in Visual Studio
3. Make sure project is set to Unicode (Properties → Advanced → Character Set)
4. Build it (Ctrl+Shift+B)
5. Run Visual Studio as Administrator, then hit F5

### Quick Note
The exe needs admin privileges or it can't check everything properly. Right-click and "Run as Administrator" if you're running it outside VS.

## Sample Output

```
================================================
   VM & Remote Access Detection System v1.0
================================================

>>> RUNNING VM DETECTION CHECKS <<<

[*] Checking VM registry keys...
    [+] No VM registry keys detected
[*] Checking VM-specific files...
    [!] VM DETECTED: File found - C:\Windows\System32\drivers\VBoxGuest.sys
[*] Checking for VM processes...
    [!] VM DETECTED: Process found - VBoxTray.exe

>>> RUNNING REMOTE ACCESS DETECTION CHECKS <<<

[*] Checking for RDP session...
    [+] No RDP session detected
[*] Checking for remote access software...
    [+] No remote access software detected

================================================
   DETECTION SUMMARY
================================================
[!!!] ALERT: Virtual Machine environment detected!
[OK] No remote access detected
```

## Current Limitations

These detection methods are honestly pretty easy to bypass:
- Registry keys can be deleted or hidden
- Files can be renamed or removed
- Processes can be disguised or terminated
- Some VM software has built-in "stealth" modes

That's the whole point of the research phase - finding better, harder-to-evade methods.

## What's Next (Research Phase)

Things I'm currently researching and planning to add:

**Hardware-level detection**
- CPUID instruction analysis - VMs respond differently to certain CPU instructions
- Timing attacks - VMs have measurable performance overhead
- Hardware fingerprinting - MAC addresses, serial numbers that look suspicious

**Behavioral detection**
- Memory artifacts that VMs leave behind
- Network configuration patterns (bridged vs NAT)
- Display and screen resolution anomalies
- Clipboard behavior (shared clipboard detection)

**Screen sharing specific**
- Zoom/Teams/Discord detection
- Multiple monitor setups
- Streaming software processes

**Anti-evasion**
- Detecting when someone's trying to hide their VM
- Checking for paravirtualization
- Nested virtualization detection

Most of these are complex and I'm still figuring out the best approaches. The code will get updated as I validate each method.

## Future Plans

In no particular order:
- Add continuous monitoring instead of one-time scan
- Build a proper logging system
- Maybe add a GUI (console works for now)
- Real-time alerts
- Better evasion resistance
- Testing on more VM types (QEMU, Parallels, etc.)

## Why This Exists

This is part of a research project to understand online exam security from a technical perspective. The goal is to:
- Figure out how people actually cheat using VMs and remote access
- Identify what traces these tools leave behind
- Build detection methods that actually work
- Understand the cat-and-mouse game between detection and evasion

This is for learning and research. Not for actual surveillance or doing anything sketchy.

##  Roadmap

### Phase 1: Foundation ✓
Basic detection skeleton with registry, files, and process scanning

### Phase 2: Research (Current)
Testing different detection methods, documenting what works and what doesn't

### Phase 3: Advanced Detection
Adding CPUID, timing attacks, hardware checks, screen sharing detection

### Phase 4: Polish
Continuous monitoring, logging, maybe a GUI, proper documentation

## Contributing

If you're researching similar stuff or have ideas:
- Found a new detection method? Cool, share it
- Know how to bypass something? Even better - helps me improve
- Documentation improvements welcome
- Test results from different VMs/setups would be helpful

Just open an issue or PR. This is a learning project so I'm open to suggestions.

## Notes

- This is my first time doing Windows system programming, so the code might not be perfect
- Testing on different VM setups and documenting results as I go
- Some detection methods I'm researching might not make it into the final version if they're too unreliable
- Working on this with a deadline, so updates might come in bursts

## Disclaimer

Built for research and learning. Don't use this to spy on people or do anything unethical. I'm not responsible if you misuse it. Get proper authorization before testing this on any system you don't own.

---

Made by Shikher Jha | Last updated: Dec 2025
