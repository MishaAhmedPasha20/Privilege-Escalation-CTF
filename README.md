Privilege Escalation CTF
You've landed a low-privilege shell (`ctfuser`) on a misconfigured Ubuntu Server box. Somewhere in the system are four independent privilege escalation vectors — real misconfigurations, not simulated ones. Escalate to root and capture all four flags.
Flags are in the format `FLAG{...}`. Submit them through the included C++ harness to verify and score your progress.
Download the Challenge VM
Download both files from this repo's Releases page:
`privesc-ctf.ova.part001`
`privesc-ctf.ova.part002`
Put them in the same folder, then rejoin them into the original file:
Windows (PowerShell):
```powershell
cmd /c copy /b privesc-ctf.ova.part001+privesc-ctf.ova.part002 privesc-ctf.ova
```
Linux/Mac:
```bash
cat privesc-ctf.ova.part001 privesc-ctf.ova.part002 > privesc-ctf.ova
```
Then import `privesc-ctf.ova` into VirtualBox: File → Import Appliance.
Setup
Boot the VM and log in as `user` (password: `1234`). Generate fresh, randomized flags for this install:
```bash
sudo bash scripts/generate_flags.sh
```
This places four flags under `/root/` and stores only their SHA-256 hashes locally in `flags.hash` — no answers ship with the repo.
Running the challenge (as an attacker)
From a separate attacking machine (Kali Linux recommended) on the same network as the VM:
```bash
ssh ctfuser@<vm-ip>
```
(`ctfuser` password: `1234`)
Enumerate the system (`sudo -l`, `find / -perm -4000`, `crontab -l`, `ls -la /etc/passwd`, etc.), find and exploit each misconfiguration, then submit captured flags:
```bash
sudo apt install g++ libssl-dev -y
g++ -std=c++17 -pthread harness/harness.cpp -o harness/harness -lssl -lcrypto
./harness/harness
```
Commands inside the harness: `enum <cmd>` · `submit <id> <flag>` · `score` · `quit`
What's inside
`misconfig4-suid-binary/vuln.c` — a custom SUID-root binary with a real vulnerability to find
`scripts/generate_flags.sh` — flag generator
`harness/harness.cpp` — C++ orchestration layer (process management, threading, synchronization, flag verification, logging)
`report/REPORT.md` — full technical writeup of each vulnerability and exploit
Note
Credentials are fixed for reproducibility, not hardened — treat this VM as "assume compromised" and never expose it beyond an isolated lab network.
Team
Misha Ahmed Pasha · Hiba Khan · Wajiha
