// ssl_bypass_ipo_v2.js
// Frida script — SSL/TLS bypass for IPO System
// V2 CHANGE: Surgical DNS hook — only patches gethostbyname (typically used for
// validation checks), NOT getaddrinfo (used for actual socket connections).
// This allows the hosts file redirect to 127.0.0.1 (Burp) to work properly
// while still defeating loopback detection in .NET's Dns.GetHostAddresses.

'use strict';

const CONFIG = {
    verbose: true,
    bypass_cert_validation: true,
    bypass_url_validation: true,
    bypass_dns_loopback_check: true,        // can disable for testing
    bypass_getaddrinfo: false,              // NEW: keep FALSE so connection uses hosts file
    bypass_proxy_detection: true,
    log_only_mode: false,
};

function log(msg) { if (CONFIG.verbose) console.log("[ssl-bypass] " + msg); }
function ok(msg)  { console.log("[+] " + msg); }
function info(msg){ console.log("[*] " + msg); }
function warn(msg){ console.log("[!] " + msg); }

function findExport(moduleName, exportName) {
    try {
        const mod = Process.findModuleByName(moduleName);
        if (!mod) return null;
        return mod.findExportByName(exportName);
    } catch (e) { return null; }
}

function tryAttach(addr, callbacks, label) {
    if (!addr) { warn("Skipped: " + label + " (not found)"); return false; }
    try { Interceptor.attach(addr, callbacks); ok("Hooked: " + label); return true; }
    catch (e) { warn("Failed to hook " + label + ": " + e.message); return false; }
}

// =============== LAYER 1 — Cert chain validation bypass ===============
function hookCertChainValidation() {
    info("Installing cert chain validation bypass...");

    tryAttach(findExport("crypt32.dll", "CertVerifyCertificateChainPolicy"), {
        onEnter: function(args) { this.pPolicyStatus = args[3]; },
        onLeave: function(retval) {
            if (CONFIG.log_only_mode) return;
            try {
                if (this.pPolicyStatus && !this.pPolicyStatus.isNull()) {
                    this.pPolicyStatus.add(4).writeU32(0);
                    this.pPolicyStatus.add(8).writeU32(0xFFFFFFFF);
                    this.pPolicyStatus.add(12).writeU32(0xFFFFFFFF);
                }
                retval.replace(ptr(1));
                log("CertVerifyCertificateChainPolicy -> forced success");
            } catch (e) {}
        }
    }, "crypt32!CertVerifyCertificateChainPolicy");

    tryAttach(findExport("crypt32.dll", "CertGetCertificateChain"), {
        onEnter: function(args) { this.ppChain = args[6]; },
        onLeave: function(retval) {
            if (CONFIG.log_only_mode) return;
            try {
                if (this.ppChain && !this.ppChain.isNull()) {
                    const pChain = this.ppChain.readPointer();
                    if (!pChain.isNull()) {
                        pChain.add(4).writeU32(0);
                        pChain.add(8).writeU32(0);
                    }
                }
            } catch (e) {}
        }
    }, "crypt32!CertGetCertificateChain");

    tryAttach(findExport("crypt32.dll", "CertVerifyRevocation"), {
        onLeave: function(retval) {
            if (CONFIG.log_only_mode) return;
            retval.replace(ptr(1));
        }
    }, "crypt32!CertVerifyRevocation");
}

// =============== LAYER 4 — SURGICAL DNS hook ===============
// Key change: only hook gethostbyname (used by older code and many validation
// routines). DO NOT hook getaddrinfo by default — that's what the actual
// socket-connection path uses. By leaving getaddrinfo alone, the OS hands the
// app the hosts file's answer (127.0.0.1), and the app connects to Burp.

function hookDnsLoopbackCheck() {
    if (!CONFIG.bypass_dns_loopback_check) return;
    info("Installing surgical DNS/loopback bypass (gethostbyname only)...");

    const FAKE_REAL_IP = [10, 34, 100, 32];

    tryAttach(findExport("ws2_32.dll", "gethostbyname"), {
        onEnter: function(args) {
            try { this.hostname = args[0].readCString(); log("gethostbyname('" + this.hostname + "')"); }
            catch (e) {}
        },
        onLeave: function(retval) {
            if (CONFIG.log_only_mode || retval.isNull()) return;
            try {
                const addrListOff = (Process.pointerSize === 8) ? 24 : 12;
                const addrList = retval.add(addrListOff).readPointer();
                if (addrList.isNull()) return;

                let i = 0;
                while (true) {
                    const addrPtr = addrList.add(i * Process.pointerSize).readPointer();
                    if (addrPtr.isNull()) break;
                    const b0 = addrPtr.readU8();
                    if (b0 === 127) {
                        const b1 = addrPtr.add(1).readU8();
                        const b2 = addrPtr.add(2).readU8();
                        const b3 = addrPtr.add(3).readU8();
                        log("gethostbyname: replacing 127." + b1 + "." + b2 + "." + b3 +
                            " -> " + FAKE_REAL_IP.join("."));
                        addrPtr.writeU8(FAKE_REAL_IP[0]);
                        addrPtr.add(1).writeU8(FAKE_REAL_IP[1]);
                        addrPtr.add(2).writeU8(FAKE_REAL_IP[2]);
                        addrPtr.add(3).writeU8(FAKE_REAL_IP[3]);
                    }
                    i++;
                    if (i > 16) break;
                }
            } catch (e) {}
        }
    }, "ws2_32!gethostbyname");

    // getaddrinfo INTENTIONALLY NOT HOOKED unless explicitly enabled.
    // The actual TCP connection uses this — we want it to return 127.0.0.1
    // so the app connects to Burp.
    if (CONFIG.bypass_getaddrinfo) {
        warn("getaddrinfo hook ENABLED — this may bypass Burp's redirect!");
        // ... if you ever need it, paste the original getaddrinfo hook here
    }
}

// =============== LAYER 5 — Proxy detection ===============
function hookProxyDetection() {
    if (!CONFIG.bypass_proxy_detection) return;
    info("Installing proxy detection bypass...");

    tryAttach(findExport("winhttp.dll", "WinHttpGetProxyForUrl"), {
        onLeave: function(retval) {
            if (CONFIG.log_only_mode) return;
            retval.replace(ptr(0));
        }
    }, "winhttp!WinHttpGetProxyForUrl");
}

// =============== LAYER 6 — Anti-debug ===============
function hookAntiDebug() {
    info("Installing anti-debug bypass...");

    tryAttach(findExport("kernel32.dll", "IsDebuggerPresent"), {
        onLeave: function(retval) {
            if (CONFIG.log_only_mode) return;
            retval.replace(ptr(0));
        }
    }, "kernel32!IsDebuggerPresent");

    tryAttach(findExport("kernel32.dll", "CheckRemoteDebuggerPresent"), {
        onEnter: function(args) { this.pIsDebugged = args[1]; },
        onLeave: function(retval) {
            if (CONFIG.log_only_mode) return;
            try {
                if (this.pIsDebugged && !this.pIsDebugged.isNull()) this.pIsDebugged.writeU32(0);
                retval.replace(ptr(1));
            } catch (e) {}
        }
    }, "kernel32!CheckRemoteDebuggerPresent");

    tryAttach(findExport("ntdll.dll", "NtQueryInformationProcess"), {
        onEnter: function(args) { this.cls = args[1].toInt32(); this.pInfo = args[2]; },
        onLeave: function(retval) {
            if (CONFIG.log_only_mode) return;
            try {
                if (retval.toInt32() === 0 && this.pInfo && !this.pInfo.isNull()) {
                    if (this.cls === 7 || this.cls === 0x1E) this.pInfo.writePointer(ptr(0));
                    else if (this.cls === 0x1F) this.pInfo.writeU32(1);
                }
            } catch (e) {}
        }
    }, "ntdll!NtQueryInformationProcess");
}

// =============== LAYER 8 — Diagnostics ===============
function installDiagnostics() {
    tryAttach(findExport("ws2_32.dll", "connect"), {
        onEnter: function(args) {
            try {
                const sockaddr = args[1];
                const family = sockaddr.readU16();
                if (family === 2) {
                    const portRaw = sockaddr.add(2).readU16();
                    const port = ((portRaw & 0xff) << 8) | ((portRaw >>> 8) & 0xff);
                    const b0 = sockaddr.add(4).readU8();
                    const b1 = sockaddar.add(5).readU8();
                    const b2 = sockaddr.add(6).readU8();
                    const b3 = sockaddr.add(7).readU8();
                    console.log("[CONNECT] " + b0 + "." + b1 + "." + b2 + "." + b3 + ":" + port);
                }
            } catch (e) {}
        }
    }, "ws2_32!connect (diagnostic)");
}

// =============== MAIN ===============
console.log("=".repeat(70));
console.log(" IPO System — SSL/TLS bypass V2 (surgical DNS)");
console.log(" Frida version: " + Frida.version);
console.log(" Process: " + Process.name + " (PID " + Process.id + ")");
console.log(" Architecture: " + Process.arch + " (pointer size " + Process.pointerSize + ")");
console.log("=".repeat(70));

if (CONFIG.bypass_cert_validation) hookCertChainValidation();
hookDnsLoopbackCheck();
if (CONFIG.bypass_proxy_detection) hookProxyDetection();
hookAntiDebug();
installDiagnostics();

console.log("\n[*] V2 hooks installed.");
console.log("[*] Watch [CONNECT] lines — destination should be 127.0.0.1:443 (Burp)");
console.log("[*] If you see direct connect to 10.34.100.32, the DNS hook is overreaching.\n");
