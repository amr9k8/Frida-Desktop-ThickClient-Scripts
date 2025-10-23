// pretty_net.js
// Frida script: socket mapping + pretty, human-readable console output.
// Usage: frida -p <pid> -l pretty_net.js

var MAX_CAPTURE = 4096;     // how many bytes to read from buffers (tune if needed)
var MAX_PRINT = 800;        // how many ascii chars to print before truncating
var socketMap = {};         // key: ptr.toString() -> { ip, port, family }

function ntohs(be16) { return ((be16 & 0xff) << 8) | ((be16 >> 8) & 0xff); }

function bytesToAscii(byteArray) {
    if (!byteArray) return "";
    var arr = new Uint8Array(byteArray);
    var s = "";
    for (var i = 0; i < arr.length; i++) {
        var ch = arr[i];
        if (ch === 9) s += '\t';
        else if (ch === 10) s += '\n';
        else if (ch === 13) s += '\r';
        else if (ch >= 32 && ch <= 126) s += String.fromCharCode(ch);
        else s += '.';
    }
    return s;
}

function safeReadCString(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try { return Memory.readUtf8String(ptr); } catch (e) { try { return Memory.readAnsiString(ptr); } catch (e2) { return null; } }
}

function sockKeyFromPtr(ptr) {
    if (!ptr) return null;
    try { return ptr.toString(); } catch (e) { return null; }
}

function parseSockaddr(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try {
        var family = Memory.readU16(ptr);
        if (family === 2) { // AF_INET
            var portBE = Memory.readU16(ptr.add(2));
            var port = ntohs(portBE);
            var addrLE = Memory.readU32(ptr.add(4));
            var b1 = addrLE & 0xff, b2 = (addrLE >> 8) & 0xff, b3 = (addrLE >> 16) & 0xff, b4 = (addrLE >> 24) & 0xff;
            return { family: 'AF_INET', ip: [b1,b2,b3,b4].join('.'), port: port };
        } else if (family === 23 || family === 10) { // AF_INET6
            var portBE = Memory.readU16(ptr.add(2));
            var port = ntohs(portBE);
            var bytes = Memory.readByteArray(ptr.add(8), 16);
            var arr = new Uint8Array(bytes);
            var words = [];
            for (var i = 0; i < 16; i += 2) words.push(((arr[i] << 8) | arr[i+1]).toString(16));
            return { family: 'AF_INET6', ip: words.join(':'), port: port };
        } else {
            return { family: family };
        }
    } catch (e) {
        return null;
    }
}

function readBuffer(ptr, length, maxLen) {
    if (!ptr || ptr.isNull() || length <= 0) return { ascii: "", len: 0 };
    var toRead = Math.min(length, maxLen || MAX_CAPTURE);
    try {
        var raw = Memory.readByteArray(ptr, toRead);
        return { ascii: bytesToAscii(raw), len: toRead };
    } catch (e) {
        return { ascii: "", len: 0 };
    }
}

function truncateForPrint(s, max) {
    if (!s) return "";
    if (s.length <= max) return s;
    return s.slice(0, max) + "\n--- (truncated, " + s.length + " bytes) ---";
}

function prettyHeader(time, type, sockKey, ip, port) {
    var ts = time || (new Date()).toISOString();
    var dir = (type || "").toUpperCase();
    var sock = sockKey || "(unknown)";
    var hostport = ip ? (ip + ":" + port) : "(unknown)";
    return ts + "  " + dir + "  sock=" + sock + "  -> " + hostport;
}

function prettyPrintPayload(ascii) {
    if (!ascii) return "";
    // keep CRLF formatting; show headers & small body
    var display = truncateForPrint(ascii, MAX_PRINT);
    // indent each line for readability
    return display.split('\n').map(function(line){ return "    " + line; }).join('\n');
}

// console-only logging (no send())
function logEvent(type, sockKey, ip, port, ascii, note) {
    var hdr = prettyHeader((new Date()).toISOString(), type, sockKey, ip, port);
    console.log(hdr);
    if (note) console.log("  [" + note + "]");
    if (ascii && ascii.length > 0) {
        console.log(prettyPrintPayload(ascii));
    }
    console.log(""); // blank line between events
}

// Try attach to exports safely
function tryHook(moduleName, exportName, onEnter, onLeave) {
    try {
        var exp = Module.findExportByName(moduleName, exportName);
        if (!exp) return false;
        Interceptor.attach(exp, { onEnter: onEnter, onLeave: onLeave });
        // print minimal startup message (not event)
        console.log("Hooked " + moduleName + "!" + exportName);
        return true;
    } catch (e) {
        console.log("Failed to hook " + moduleName + "!" + exportName + ": " + e);
        return false;
    }
}


// ------------------ Hooks ------------------

// connect(sock, sockaddr*, namelen)
tryHook("Ws2_32.dll","connect", function(args) {
    this.sockKey = sockKeyFromPtr(args[0]);
    this.sa = args[1];
    var saObj = parseSockaddr(this.sa);
    if (this.sockKey && saObj) socketMap[this.sockKey] = saObj;
    logEvent("connect", this.sockKey, saObj ? saObj.ip : null, saObj ? saObj.port : null, null);
}, function(retval){});

// WSAConnect
tryHook("Ws2_32.dll","WSAConnect", function(args) {
    this.sockKey = sockKeyFromPtr(args[0]);
    this.sa = args[1];
    var saObj = parseSockaddr(this.sa);
    if (this.sockKey && saObj) socketMap[this.sockKey] = saObj;
    logEvent("WSAConnect", this.sockKey, saObj ? saObj.ip : null, saObj ? saObj.port : null, null);
}, function(retval){});

// mswsock ConnectEx (overlapped)
tryHook("mswsock.dll","ConnectEx", function(args) {
    this.sockKey = sockKeyFromPtr(args[0]);
    this.sa = args[1];
    var saObj = parseSockaddr(this.sa);
    if (this.sockKey && saObj) socketMap[this.sockKey] = saObj;
    logEvent("ConnectEx", this.sockKey, saObj ? saObj.ip : null, saObj ? saObj.port : null, null);
}, function(retval){});

// sendto(sock, buf, len, flags, to, tolen)
tryHook("Ws2_32.dll","sendto", function(args) {
    this.sockKey = sockKeyFromPtr(args[0]);
    this.buf = args[1];
    this.len = args[2].toInt32();
    this.sa = args[4];
    var saObj = parseSockaddr(this.sa);
    if (this.sockKey && saObj) socketMap[this.sockKey] = saObj;
    var d = readBuffer(this.buf, this.len, MAX_CAPTURE);
    var peer = this.sockKey ? socketMap[this.sockKey] : null;
    // fallback parse Host header if needed
    if (!peer && d.ascii) {
        var m = d.ascii.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
        if (m) peer = { ip: m[1], port: m[2] ? parseInt(m[2]) : 80 };
    }
    logEvent("SEND", this.sockKey, peer ? peer.ip : null, peer ? peer.port : null, d.ascii);
}, function(retval){});

// send(sock, buf, len, flags)
tryHook("Ws2_32.dll","send", function(args) {
    this.sockKey = sockKeyFromPtr(args[0]);
    this.buf = args[1];
    this.len = args[2].toInt32();
    var d = readBuffer(this.buf, this.len, MAX_CAPTURE);
    var peer = this.sockKey ? socketMap[this.sockKey] : null;
    if (!peer && d.ascii) {
        var m = d.ascii.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
        if (m) peer = { ip: m[1], port: m[2] ? parseInt(m[2]) : 80 };
    }
    logEvent("SEND", this.sockKey, peer ? peer.ip : null, peer ? peer.port : null, d.ascii);
}, function(retval){});

// WSASend (WSABUF array)
tryHook("Ws2_32.dll","WSASend", function(args) {
    this.sockKey = sockKeyFromPtr(args[0]);
    this.lpBuffers = args[1];
    this.dwBufferCount = args[2].toInt32();
    try {
        var firstLen = Memory.readU32(this.lpBuffers);
        var firstBufPtr = Memory.readPointer(this.lpBuffers.add(Process.pointerSize));
        var d = readBuffer(firstBufPtr, firstLen, MAX_CAPTURE);
        var peer = this.sockKey ? socketMap[this.sockKey] : null;
        if (!peer && d.ascii) {
            var m = d.ascii.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
            if (m) peer = { ip: m[1], port: m[2] ? parseInt(m[2]) : 80 };
        }
        logEvent("SEND", this.sockKey, peer ? peer.ip : null, peer ? peer.port : null, d.ascii, "WSASend buffers=" + this.dwBufferCount);
    } catch (e) {
        logEvent("SEND", this.sockKey, null, null, null, "WSASend (couldn't read buffers)");
    }
}, function(retval){});

// recv
tryHook("Ws2_32.dll","recv", function(args) {
    this.sockKey = sockKeyFromPtr(args[0]);
    this.buf = args[1];
    this.len = args[2].toInt32();
}, function(retval) {
    var got = retval.toInt32();
    if (got > 0) {
        var d = readBuffer(this.buf, got, MAX_CAPTURE);
        var peer = this.sockKey ? socketMap[this.sockKey] : null;
        logEvent("RECV", this.sockKey, peer ? peer.ip : null, peer ? peer.port : null, d.ascii);
    }
});

// recvfrom
tryHook("Ws2_32.dll","recvfrom", function(args) {
    this.sockKey = sockKeyFromPtr(args[0]);
    this.buf = args[1];
    this.len = args[2].toInt32();
    this.addr = args[4];
}, function(retval) {
    var got = retval.toInt32();
    var sa = parseSockaddr(this.addr);
    if (got > 0) {
        var d = readBuffer(this.buf, got, MAX_CAPTURE);
        logEvent("RECVFROM", this.sockKey, sa ? sa.ip : null, sa ? sa.port : null, d.ascii);
    }
});

// closesocket
tryHook("Ws2_32.dll","closesocket", function(args) {
    this.sockKey = sockKeyFromPtr(args[0]);
    if (this.sockKey && socketMap[this.sockKey]) {
        logEvent("CLOSE", this.sockKey, socketMap[this.sockKey].ip, socketMap[this.sockKey].port, null);
        delete socketMap[this.sockKey];
    } else {
        logEvent("CLOSE", this.sockKey, null, null, null);
    }
}, function(retval){});

// DNS lookups
tryHook("Ws2_32.dll","getaddrinfo", function(args) {
    this.node = args[0];
    this.service = args[1];
    this.node_s = safeReadCString(this.node);
    this.service_s = safeReadCString(this.service);
    logEvent("DNS-LOOKUP", null, this.node_s, this.service_s, null);
}, function(retval){});
tryHook("Ws2_32.dll","gethostbyname", function(args) {
    this.name = args[0];
    this.name_s = safeReadCString(this.name);
    logEvent("DNS-LOOKUP", null, this.name_s, null, null);
}, function(retval){});

// WinHTTP / WinINet high-level connect hints
tryHook("winhttp.dll","WinHttpConnect", function(args) {
    var server = args[1] ? Memory.readUtf16String(args[1]) : null;
    var port = args[2].toInt32();
    logEvent("WINHTTP", null, server, port, null);
});
tryHook("wininet.dll","InternetConnectA", function(args) {
    var server = safeReadCString(args[1]);
    var port = args[2].toInt32();
    logEvent("WININET", null, server, port, null);
});

console.log("Pretty network logger installed. Only human-readable events will be printed.");
setInterval(function(){}, 10000);
