# CyberArk AIM → Veeam Credentials Sync (PowerShell)

Sync secrets stored in **CyberArk (AIM WebService)** into **Veeam Backup & Replication** credentials automatically.  
Typical use-case: CyberArk rotates Linux account passwords, and Veeam needs the updated credentials for managed servers, repositories, or guest processing.

> This project is not affiliated with CyberArk or Veeam.

---

## What it does

For each CyberArk **Object** you provide, the script:

1. Calls CyberArk **AIMWebService** (REST endpoint) to retrieve `UserName` and `Content` (password).
2. Converts the password to a `SecureString` (in-memory).
3. Adds or updates a **Linux** credential in **Veeam Credentials Manager**.
4. Writes a local log file and prints a summary report.

**Matching logic in Veeam:**  
The script updates an existing credential when it finds a Linux credential with:
- same `UserName`
- and a `Description` containing `Object=<YourObjectName>`

This prevents duplicates when the same username exists for multiple targets/objects.

---

## Requirements

### On the Veeam server
- Run on the **Veeam Backup & Replication** server (or a machine that can access the VBR server and has the Veeam PowerShell module available).
- PowerShell **5.1** or **7+**
- Veeam PowerShell module:
  - `Veeam.Backup.PowerShell`

### On the CyberArk side
- CyberArk **AIM WebService** reachable from the Veeam server
- An **AppID** configured for your application
- Permissions to read secrets from the specified **Safe/Folder/Object**
- The AIM endpoint must return either:
  - JSON containing `UserName` and `Content`, OR
  - XML containing nodes `//UserName` and `//Content`

---

## Security notes (important)

- The script **does not log passwords**.
- The script **can** skip TLS certificate validation **only if you explicitly enable it** (`-SkipCertificateCheck`).
  - Use this only if you understand the risk (MITM / interception).
  - Best practice: install a trusted certificate chain on the CyberArk web service instead.

- Run the script under an account that has:
  - rights to manage Veeam credentials
  - network access to the CyberArk AIM endpoint

---

## Repository layout (suggested)

```text
.
├─ src/
│  └─ CyberArk-VeeamCredsSync.ps1
├─ examples/
│  ├─ objects.txt
│  └─ config.example.psd1
├─ LICENSE
├─ SECURITY.md
└─ README.md
