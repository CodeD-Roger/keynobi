# 🧙‍♂️ keynobi.sh — The Certificate Is Strong With This One

**keynobi** is a Bash-powered Jedi that roams your Linux system, detects SSL/TLS certificates, SSH keys, and PGP keys, then reveals their secrets like a true master of the terminal Force.

No more wondering where your `.crt`, `.pem`, `.key`, or `.asc` files are hiding. keynobi hunts them down, filters them interactively, and tells you what’s valid, what’s expiring, and what’s encrypted.

> "A long time ago, in a datacenter far, far away, a sysadmin lost track of his SSL certs. Until keynobi arrived..."

---

## ✨ Features Overview

| Feature                                      | Description                                                                 |
|---------------------------------------------|-----------------------------------------------------------------------------|
| 🔍 Full system scan                         | Searches for SSL/TLS, SSH, and PGP keys across your Linux filesystem       |
| 🧠 Smart filtering for SSL/TLS               | Filter certs by domain, issuer, or expiration (e.g., "expiring in 30 days")|
| 🔐 Passphrase detection                     | Detects certs or keys that require a passphrase and warns you              |
| 📂 Directory-based results                  | Shows where your certs are located and how many per folder                 |
| 📊 Interactive, color-coded display         | Clear and clean terminal UI for human-friendly navigation                  |
| 🚫 System noise reduction                   | Automatically excludes irrelevant system paths (e.g., `/usr/share`)        |
| 🕹️ Terminal menu                           | Explore certs by type: SSL/TLS, SSH, PGP, all-in-one, or filter setup      |
| 🧼 Auto-clean temporary files               | Leaves no trace after execution                                            |

---

## 🚀 Installation & Usage

1️⃣ Clone the repository & run

```bash
git clone https://github.com/CodeD-Roger/keynobi.git
cd keynobi
sudo chmod +x keynobi.sh
./keynobi.sh
```
