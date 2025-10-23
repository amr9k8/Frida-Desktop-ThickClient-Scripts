

// capture_db_traffic_merged.js
// Frida script to capture DB-related traffic and DB-client API usage
// - Winsock (send/recv/sendto/recvfrom/WSASend/WSARecv/connect/getpeername)
// - Named pipes (CreateFileW, ReadFile, WriteFile, TransactNamedPipe)
// - ODBC (SQLDriverConnect/SQLConnect/SQLExecDirect)
// - SQLite (sqlite3_exec, sqlite3_prepare_v2) if present
// - MySQL (mysql_query) if present
// - PostgreSQL (PQexec) if present
// - WinHTTP (WinHttpSendRequest) for header capture
//
// NOTE: Do NOT define a global 'hexdump' — Frida already exposes one. Use dumpMemory().

////////////////////////////////////////////////////////////////////////////////
// CONFIG - tune these for your target
var FILTER_PORTS = [1433];                                 // DB ports of interest
var FILTER_IPS = ["127.0.0.1", "localhost", "::1"];        // address substrings
var FILTER_PIPE_SUBSTRS = ["\\pipe\\", "sql", "mssql"];    // pipe path substrings
var MAX_DUMP = 4096;                                       // bytes to capture per call
var MAX_STR_LEN = 2048;                                    // max length when reading strings
////////////////////////////////////////////////////////////////////////////////

// --------------------- Utilities ---------------------
function u16_be(v) { return ((v & 0xff) << 8) | ((v >>> 8) & 0xff); }

function bytesToHex(arr) {
    if (!arr) return "";
    var s = [];
    for (var i = 0; i < arr.length; i++) {
        s.push(('0' + arr[i].toString(16)).slice(-2));
    }
    return s.join('');
}
function bytesToAscii(arr) {
    if (!arr) return "";
    var s = "";
    for (var i = 0; i < arr.length; i++) {
        var ch = arr[i];
        s += (ch >= 32 && ch <= 126) ? String.fromCharCode(ch) : '.';
    }
    return s;
}

// Safe memory read into hex+ascii summary
function dumpMemory(ptr, len) {
    try {
        if (!ptr || len <= 0) return { hex: "", ascii: "", length: 0 };
        var readLen = Math.min(len, MAX_DUMP);
        var ba = Memory.readByteArray(ptr, readLen);
        if (!ba) return { hex: "", ascii: "", length: 0 };
        var u8 = new Uint8Array(ba);
        return { hex: bytesToHex(u8), ascii: bytesToAscii(u8), length: u8.length };
    } catch (e) {
        return { hex: "<err>", ascii: "<err>", length: 0 };
    }
}

// Pretty formatted hex dump (non-conflicting name)
function formattedHexDump(ptr, len) {
    try {
        if (!ptr || len <= 0) return "";
        var readLen = Math.min(len, MAX_DUMP);
        var ba = Memory.readByteArray(ptr, readLen);
        if (!ba) return "";
        var u8 = new Uint8Array(ba);
        var out = "\n";
        for (var i = 0; i < u8.length; i += 16) {
            var slice = u8.slice(i, Math.min(i + 16, u8.length));
            var hex = Array.prototype.map.call(slice, function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
            var ascii = Array.prototype.map.call(slice, function(b) { return (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.'; }).join('');
            out += "  " + ('00000000' + i.toString(16)).slice(-8) + ": " + hex.padEnd(47, ' ') + " | " + ascii + "\n";
        }
        return out;
    } catch (e) {
        return "[formattedHexDump error]";
    }
}

// Safely read a UTF-8 or UTF-16 string with max length and checks
function safeReadString(ptr, isWide, maxLen) {
    maxLen = maxLen || MAX_STR_LEN;
    try {
        if (!ptr || ptr.isNull()) return null;
        if (isWide) {
            // Attempt readUtf16String but guard length
            var s = Memory.readUtf16String(ptr, maxLen);
            if (s && s.length > 0) return s;
            return null;
        } else {
            var s = Memory.readUtf8String(ptr, maxLen);
            if (s && s.length > 0) return s;
            return null;
        }
    } catch (e) {
        // Fallback: try reading bytes and convert
        try {
            var ba = Memory.readByteArray(ptr, Math.min(maxLen, 512));
            if (!ba) return null;
            var u8 = new Uint8Array(ba);
            var out = "";
            for (var i = 0; i < u8.length; i++) {
                if (u8[i] === 0) break;
                out += String.fromCharCode(u8[i]);
            }
            return out;
        } catch (e2) {
            return null;
        }
    }
}

// Parse sockaddr_in stored in memory -> {ip, port}
function parseSockaddr(ptr) {
    try {
        if (!ptr || ptr.isNull()) return { ip: "<null>", port: 0 };
        var fam = Memory.readU16(ptr);
        if (fam === 2) { // AF_INET
            // port at offset 2 big-endian
            var portRaw = Memory.readU16(ptr.add(2));
            var port = u16_be(portRaw);
            var b0 = Memory.readU8(ptr.add(4));
            var b1 = Memory.readU8(ptr.add(5));
            var b2 = Memory.readU8(ptr.add(6));
            var b3 = Memory.readU8(ptr.add(7));
            return { ip: [b0,b1,b2,b3].join('.'), port: port };
        } else {
            return { ip: "<non-IPv4>", port: 0 };
        }
    } catch (e) {
        return { ip: "<err>", port: 0 };
    }
}

// getpeername wrapper to learn remote endpoint for a socket
var getPeerNameFn = null;
try {
    var getpeer = Module.findExportByName("ws2_32.dll", "getpeername");
    if (getpeer) {
        getPeerNameFn = new NativeFunction(getpeer, 'int', ['int', 'pointer', 'pointer']);
    }
} catch (e) { /* ignore */ }

function getPeerInfo(socket) {
    try {
        if (!getPeerNameFn) return null;
        var addr = Memory.alloc(128);
        Memory.writeByteArray(addr, Array(128).fill(0));
        var addrLen = Memory.alloc(Process.pointerSize);
        Memory.writeUInt(addrLen, 16);
        var r = getPeerNameFn(socket, addr, addrLen);
        if (r === 0) return parseSockaddr(addr);
    } catch (e) { /* ignore */ }
    return null;
}

// Logging helper
function logTraffic(direction, proto, endpoint, dataPtr, dataLen) {
    try {
        var dumpLen = Math.min(dataLen | 0, MAX_DUMP);
        var d = dumpMemory(dataPtr, dumpLen);
        var summary = {
            time: (new Date()).toISOString(),
            pid: Process.id,
            proc: Process.name,
            direction: direction,
            proto: proto,
            endpoint: endpoint,
            length: dataLen,
            dump_len: d.length || d.length === 0 ? d.length : dumpLen,
            ascii_preview: d.ascii ? d.ascii.slice(0, 200) : "",
        };
        console.log("=== DB TRAFFIC ===");
        console.log(JSON.stringify(summary, null, 2));
        if (d.hex && d.hex.length > 0) {
            console.log(formattedHexDump(dataPtr, dumpLen));
        }
    } catch (e) {
        console.log("logTraffic error:", e);
    }
}

// --------------------- Winsock hooks ---------------------
function hookWinsock() {
    var names = ["send", "recv", "sendto", "recvfrom", "connect", "WSASend", "WSARecv"];
    names.forEach(function(name) {
        var addr = Module.findExportByName("ws2_32.dll", name);
        if (!addr) return;
        try {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    this.fn = name;
                    try {
                        if (name === "connect") {
                            this.socket = args[0].toInt32();
                            this.sockaddr = args[1];
                            try {
                                var info = parseSockaddr(this.sockaddr);
                                this.connect_target = info;
                            } catch (e) { }
                        } else if (name === "send" || name === "recv") {
                            this.socket = args[0].toInt32();
                            this.buf = args[1];
                            this.len = args[2].toInt32();
                            var p = getPeerInfo(this.socket);
                            if (p) {
                                var endpointStr = p.ip + ":" + p.port;
                                if (FILTER_IPS.some(function(x){ return endpointStr.indexOf(x) !== -1; }) ||
                                    FILTER_PORTS.indexOf(p.port) !== -1) {
                                    var dir = (name === "send") ? "out" : "in";
                                    logTraffic(dir, "tcp", endpointStr, this.buf, this.len);
                                }
                            }
                        } else if (name === "sendto") {
                            this.socket = args[0].toInt32();
                            this.buf = args[1];
                            this.len = args[2].toInt32();
                            var toPtr = args[4];
                            var toInfo = parseSockaddr(toPtr);
                            var endpointStr = toInfo.ip + ":" + toInfo.port;
                            if (FILTER_IPS.some(function(x){ return endpointStr.indexOf(x) !== -1; }) ||
                                FILTER_PORTS.indexOf(toInfo.port) !== -1) {
                                logTraffic("out", "udp/tcp", endpointStr, this.buf, this.len);
                            }
                        } else if (name === "recvfrom") {
                            this.socket = args[0].toInt32();
                            this.buf = args[1];
                            this.len = args[2].toInt32();
                        } else if (name === "WSASend") {
                            this.socket = args[0].toInt32();
                            this.bufArray = args[1];
                            this.bufCount = args[2].toInt32();
                            var endpoint = getPeerInfo(this.socket);
                            var endpointStr = endpoint ? endpoint.ip + ":" + endpoint.port : "<unknown>";
                            for (var i=0;i<this.bufCount;i++) {
                                try {
                                    // WSABUF structure: ULONG len; CHAR *buf;
                                    var base = this.bufArray.add(i * Process.pointerSize * 2);
                                    var buflen = Memory.readU32(base);
                                    var bufptr = Memory.readPointer(base.add(Process.pointerSize));
                                    if ((endpoint && (FILTER_IPS.some(function(x){ return endpointStr.indexOf(x) !== -1; }) ||
                                        FILTER_PORTS.indexOf(endpoint.port) !== -1))) {
                                        logTraffic("out", "tcp(WSASend)", endpointStr, bufptr, buflen);
                                    }
                                } catch(e) { /* ignore individual buffer errors */ }
                            }
                        } else if (name === "WSARecv") {
                            this.socket = args[0].toInt32();
                            this.bufArray = args[1];
                            this.bufCount = args[2].toInt32();
                        }
                    } catch (e) {
                        // avoid breaking target process
                    }
                },
                onLeave: function (retval) {
                    try {
                        if (this.fn === "connect") {
                            if (retval.toInt32() === 0 && this.connect_target) {
                                var t = this.connect_target;
                                var endpointStr = t.ip + ":" + t.port;
                                if (FILTER_IPS.some(function(x){ return endpointStr.indexOf(x) !== -1; }) ||
                                    FILTER_PORTS.indexOf(t.port) !== -1) {
                                    console.log("[+] connect() to DB endpoint: " + endpointStr + " succeeded");
                                }
                            }
                        } else if (this.fn === "recvfrom") {
                            var got = retval.toInt32();
                            if (got > 0 && this.buf) {
                                var p = getPeerInfo(this.socket);
                                var endpointStr = p ? (p.ip + ":" + p.port) : "<unknown>";
                                if (p && (FILTER_IPS.some(function(x){ return endpointStr.indexOf(x) !== -1; }) ||
                                    FILTER_PORTS.indexOf(p.port) !== -1)) {
                                    logTraffic("in", "udp/tcp", endpointStr, this.buf, got);
                                }
                            }
                        } else if (this.fn === "WSARecv") {
                            var got = retval.toInt32();
                            var endpoint = getPeerInfo(this.socket);
                            var endpointStr = endpoint ? endpoint.ip + ":" + endpoint.port : "<unknown>";
                            if (got > 0 && this.bufArray && endpoint) {
                                for (var i=0;i<this.bufCount;i++) {
                                    try {
                                        var base = this.bufArray.add(i * Process.pointerSize * 2);
                                        var buflen = Memory.readU32(base);
                                        var bufptr = Memory.readPointer(base.add(Process.pointerSize));
                                        if ((FILTER_IPS.some(function(x){ return endpointStr.indexOf(x) !== -1; }) ||
                                            (endpoint && FILTER_PORTS.indexOf(endpoint.port) !== -1))) {
                                            logTraffic("in", "tcp(WSARecv)", endpointStr, bufptr, buflen);
                                        }
                                    } catch(e) {}
                                }
                            }
                        }
                    } catch (e) { /* ignore */ }
                }
            });
        } catch (e) {
            // ignore attach errors for each symbol
        }
    });
}

////////////////////////////////////////////////////////////////////////////////
// Named pipes & file I/O hooks (CreateFileW/ReadFile/WriteFile/TransactNamedPipe)
function hookNamedPipes() {
    var createFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
    if (createFileW) {
        Interceptor.attach(createFileW, {
            onEnter: function(args) {
                try {
                    var lpFileName = args[0];
                    var path = safeReadString(lpFileName, true, 1024);
                    this.path = path;
                    if (path && FILTER_PIPE_SUBSTRS.some(function(s){ return path.toLowerCase().indexOf(s.toLowerCase()) !== -1; })) {
                        this.is_pipe = true;
                        console.log("[+] CreateFileW -> opening suspected pipe: " + path);
                    }
                } catch (e) {}
            },
            onLeave: function(retval) {
                try {
                    if (this.is_pipe) {
                        console.log("[+] CreateFileW returned handle: " + retval);
                    }
                } catch (e) {}
            }
        });
    }

    var writeFile = Module.findExportByName("kernel32.dll", "WriteFile");
    if (writeFile) {
        Interceptor.attach(writeFile, {
            onEnter: function(args) {
                try {
                    this.hFile = args[0];
                    this.lpBuffer = args[1];
                    this.nToWrite = args[2].toInt32();
                    if (this.nToWrite > 0) {
                        var d = dumpMemory(this.lpBuffer, Math.min(this.nToWrite, MAX_DUMP));
                        console.log("[PIPE WRITE] handle=" + this.hFile + " len=" + this.nToWrite + " ascii_preview=" + (d.ascii ? d.ascii.slice(0,200) : "<empty>"));
                    }
                } catch (e) {}
            }
        });
    }

    var readFile = Module.findExportByName("kernel32.dll", "ReadFile");
    if (readFile) {
        Interceptor.attach(readFile, {
            onEnter: function(args) {
                try {
                    this.hFile = args[0];
                    this.lpBuffer = args[1];
                    this.nToRead = args[2].toInt32();
                } catch (e) {}
            },
            onLeave: function(retval) {
                try {
                    // For ReadFile, number of bytes read often passed via pointer arg[3]; we keep it simple and try to dump buffer
                    var d = dumpMemory(this.lpBuffer, Math.min(this.nToRead, MAX_DUMP));
                    if (d.length > 0) {
                        console.log("[PIPE READ] handle=" + this.hFile + " ascii_preview=" + (d.ascii ? d.ascii.slice(0,200) : "<empty>"));
                    }
                } catch (e) {}
            }
        });
    }

    var tnp = Module.findExportByName("kernel32.dll", "TransactNamedPipe");
    if (tnp) {
        Interceptor.attach(tnp, {
            onEnter: function(args) {
                try {
                    this.hPipe = args[0];
                    this.lpInBuffer = args[1];
                    this.nInBufferSize = args[2].toInt32();
                    if (this.nInBufferSize > 0) {
                        var d = dumpMemory(this.lpInBuffer, Math.min(this.nInBufferSize, MAX_DUMP));
                        console.log("[TransactNamedPipe OUT] handle=" + this.hPipe + " len=" + this.nInBufferSize + " ascii_preview=" + (d.ascii?d.ascii.slice(0,200):"<empty>"));
                    }
                } catch (e) {}
            },
            onLeave: function(retval) { /* no-op for now */ }
        });
    }
}

////////////////////////////////////////////////////////////////////////////////
// ODBC hooks (best-effort capture of connection strings and SQL)
function hookODBC() {
    var candidates = [
        "SQLDriverConnectW", "SQLDriverConnectA",
        "SQLConnectW", "SQLConnectA",
        "SQLExecDirectW", "SQLExecDirectA",
        "SQLExecute"
    ];
    candidates.forEach(function(name) {
        var addr = Module.findExportByName("odbc32.dll", name);
        if (!addr) return;
        try {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    try {
                        if (name.toLowerCase().indexOf("execdirect") !== -1) {
                            var sqlPtr = args[1];
                            var sql = name.endsWith("W") ? safeReadString(sqlPtr, true, 4096) : safeReadString(sqlPtr, false, 4096);
                            if (sql) console.log("[ODBC] " + name + " -> SQL: " + sql);
                        } else if (name.toLowerCase().indexOf("connect") !== -1) {
                            // best-effort connection string capture
                            try {
                                var maybe = args[1];
                                var s = safeReadString(maybe, true, 2048);
                                if (s) console.log("[ODBC] " + name + " -> connstr (W candidate): " + s);
                                else {
                                    var s2 = safeReadString(maybe, false, 2048);
                                    if (s2) console.log("[ODBC] " + name + " -> connstr (A candidate): " + s2);
                                }
                            } catch (e) {}
                        }
                    } catch (e) {}
                }
            });
        } catch (e) {}
    });
}

////////////////////////////////////////////////////////////////////////////////
// Module-specific DB-client hooks: SQLite, MySQL, PostgreSQL, WinHTTP
function hookModuleClients() {
    try {
        var mods = Process.enumerateModules();
        // find sqlite modules
        var sqliteMods = mods.filter(m => m.name.toLowerCase().includes('sqlite') || m.path.toLowerCase().includes('sqlite'));
        sqliteMods.forEach(function(module) {
            console.log("[*] Found SQLite module:", module.name);
            var execPtr = Module.findExportByName(module.name, "sqlite3_exec");
            if (execPtr) {
                Interceptor.attach(execPtr, {
                    onEnter: function(args) {
                        try {
                            var sqlPtr = args[1];
                            var query = safeReadString(sqlPtr, false, 4096);
                            if (query) console.log("\n[SQLite EXEC] " + query);
                        } catch (e) {}
                    }
                });
                console.log("[+] Hooked sqlite3_exec in", module.name);
            }
            var prepPtr = Module.findExportByName(module.name, "sqlite3_prepare_v2");
            if (prepPtr) {
                Interceptor.attach(prepPtr, {
                    onEnter: function(args) {
                        try {
                            var sqlPtr = args[1];
                            var query = safeReadString(sqlPtr, false, 4096);
                            if (query) console.log("\n[SQLite PREPARE] " + query);
                        } catch (e) {}
                    }
                });
                console.log("[+] Hooked sqlite3_prepare_v2 in", module.name);
            }
        });
    } catch (e) {
        console.log("[-] SQLite hook scan error:", e);
    }

    try {
        var mods = Process.enumerateModules();
        var mysqlMods = mods.filter(m => m.name.toLowerCase().includes('mysql') || m.name.toLowerCase().includes('mariadb') || m.name.toLowerCase().includes('libmysql'));
        mysqlMods.forEach(function(module) {
            console.log("[*] Found MySQL module:", module.name);
            var queryPtr = Module.findExportByName(module.name, "mysql_query");
            if (queryPtr) {
                Interceptor.attach(queryPtr, {
                    onEnter: function(args) {
                        try {
                            var query = safeReadString(args[1], false, 4096);
                            if (query) console.log("\n[MySQL QUERY] " + query);
                        } catch (e) {}
                    }
                });
                console.log("[+] Hooked mysql_query in", module.name);
            }
        });
    } catch (e) {
        console.log("[-] MySQL hook scan error:", e);
    }

    try {
        var mods = Process.enumerateModules();
        var pgMods = mods.filter(m => m.name.toLowerCase().includes('postgres') || m.name.toLowerCase().includes('libpq'));
        pgMods.forEach(function(module) {
            console.log("[*] Found PostgreSQL module:", module.name);
            var execPtr = Module.findExportByName(module.name, "PQexec");
            if (execPtr) {
                Interceptor.attach(execPtr, {
                    onEnter: function(args) {
                        try {
                            var q = safeReadString(args[1], false, 4096);
                            if (q) console.log("\n[PostgreSQL PQexec] " + q);
                        } catch (e) {}
                    }
                });
                console.log("[+] Hooked PQexec in", module.name);
            }
        });
    } catch (e) {
        console.log("[-] PostgreSQL hook scan error:", e);
    }

    // WinHTTP headers capture
    try {
        var winhttpSendPtr = Module.findExportByName("winhttp.dll", "WinHttpSendRequest");
        if (winhttpSendPtr) {
            Interceptor.attach(winhttpSendPtr, {
                onEnter: function(args) {
                    try {
                        // WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, ...)
                        var headersPtr = args[1];
                        var headersLen = args[2].toInt32();
                        var headers = null;
                        if (!headersPtr.isNull()) {
                            // if dwHeadersLength == -1, headersPtr is null-terminated; otherwise use given length
                            var isWide = true; // WinHTTP uses wide headers (LPCWSTR)
                            headers = safeReadString(headersPtr, isWide, (headersLen > 0 ? headersLen : 1024));
                        }
                        console.log("\n[WinHTTP] WinHttpSendRequest called; headers_preview:", headers ? headers.slice(0,400) : "<none>");
                    } catch (e) {}
                }
            });
            console.log("[+] Hooked WinHttpSendRequest()");
        }
    } catch (e) { /* ignore */ }
}

////////////////////////////////////////////////////////////////////////////////
// Bootstrap: install hooks
try {
    console.log("[*] Installing DB traffic & API hooks...");
    hookWinsock();
    hookNamedPipes();
    hookODBC();
    hookModuleClients();
    console.log("[*] Hooks installed. Filters: ports=" + JSON.stringify(FILTER_PORTS) + " ips=" + JSON.stringify(FILTER_IPS));
} catch (e) {
    console.log("[-] Error installing hooks:", e);
}

////////////////////////////////////////////////////////////////////////////////
// End of script
