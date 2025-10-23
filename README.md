# Frida Thick-Client Pentest Toolkit

A collection of Frida scripts to accelerate security testing of Windows thick-client applications. These scripts provide runtime visibility into crypto/decryption calls, file I/O, registry access, local database usage, proxying, and network traffic so you can quickly identify insecure data flows, weak cryptography, and exposed secrets.

---

## What's included

* `analyze_traffic_frida.js` — Inspect and log network traffic at runtime.
* `hook_Decryptions_WinApis2_Frida.js` — Hook common Windows decryption APIs to capture plaintext.
* `hook_Files_Writing_Frida.js` — Intercept file write calls to detect sensitive data written to disk.
* `hook_Registries_Frida.js` — Log registry reads/writes for possible secret storage or insecure configuration.
* `hook_local_DB_Frida.js` — Intercept access to local embedded databases (SQLite, LevelDB, etc.).
* `hook_proxy_redirect_Frida.js` — Redirect network calls to a local SOCKS/HTTP proxy for inspection( add your proxy ip and port at top of the js file).


## Quick start

> **Prerequisites:** Python & Frida tools on your workstation, and Frida server on the target (if remote).

1. Install Frida on your machine:

   ```bash
   pip install frida-tools
   ```

2. Start the target application under Frida and load a hook. Example (replace `<target.exe>`):

   ```bash
   frida -l hook_Decryptions_WinApis2_Frida.js -p <pid> 
   ```

3. Observe console output, or adapt the script to write captures to a file, database, or HTTP endpoint.

