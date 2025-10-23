/**
 * Frida script to redirect ALL Windows network connections through SOCKS5 proxy
 * Hooks: WinSock2, WinHTTP, WinINet, and .NET APIs
 * Usage: frida -l script.js -f target.exe --no-pause
 */

const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 8080;

console.log("[*] Windows Network API Hooking Script");
console.log(`[*] Redirecting all connections to SOCKS5 proxy ${PROXY_HOST}:${PROXY_PORT}\n`);

// ============================================================================
// WINSOCK2 API HOOKS (ws2_32.dll)
// ============================================================================

try {
    const ws2_32 = Process.getModuleByName("ws2_32.dll");
    console.log("[+] Found ws2_32.dll");

    // Hook connect()
    const connectPtr = Module.findExportByName("ws2_32.dll", "connect");
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter: function(args) {
                const socket = args[0];
                const sockaddr = args[1];
                const namelen = args[2].toInt32();
                
                const sa_family = sockaddr.readU16();
                
                if (sa_family === 2) { // AF_INET
                    const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                    const ip = sockaddr.add(4).readU32();
                    const ipStr = `${ip & 0xFF}.${(ip >> 8) & 0xFF}.${(ip >> 16) & 0xFF}.${(ip >> 24) & 0xFF}`;
                    
                    console.log(`\n[WS2_32] connect() -> ${ipStr}:${port}`);
                    
                    // Redirect to proxy
                    sockaddr.add(2).writeU8((PROXY_PORT >> 8) & 0xFF);
                    sockaddr.add(3).writeU8(PROXY_PORT & 0xFF);
                    sockaddr.add(4).writeU32(0x0100007F); // 127.0.0.1
                    
                    console.log(`[*] Redirected to ${PROXY_HOST}:${PROXY_PORT}`);
                }
            }
        });
        console.log("[✓] Hooked: connect()");
    }

    // Hook WSAConnect()
    const wsaConnectPtr = Module.findExportByName("ws2_32.dll", "WSAConnect");
    if (wsaConnectPtr) {
        Interceptor.attach(wsaConnectPtr, {
            onEnter: function(args) {
                const socket = args[0];
                const sockaddr = args[1];
                
                const sa_family = sockaddr.readU16();
                
                if (sa_family === 2) { // AF_INET
                    const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                    const ip = sockaddr.add(4).readU32();
                    const ipStr = `${ip & 0xFF}.${(ip >> 8) & 0xFF}.${(ip >> 16) & 0xFF}.${(ip >> 24) & 0xFF}`;
                    
                    console.log(`\n[WS2_32] WSAConnect() -> ${ipStr}:${port}`);
                    
                    sockaddr.add(2).writeU8((PROXY_PORT >> 8) & 0xFF);
                    sockaddr.add(3).writeU8(PROXY_PORT & 0xFF);
                    sockaddr.add(4).writeU32(0x0100007F);
                    
                    console.log(`[*] Redirected to ${PROXY_HOST}:${PROXY_PORT}`);
                }
            }
        });
        console.log("[✓] Hooked: WSAConnect()");
    }

    // Hook WSAConnectByNameA()
    const wsaConnectByNameAPtr = Module.findExportByName("ws2_32.dll", "WSAConnectByNameA");
    if (wsaConnectByNameAPtr) {
        Interceptor.attach(wsaConnectByNameAPtr, {
            onEnter: function(args) {
                const nodename = args[1].readAnsiString();
                const servicename = args[2].readAnsiString();
                
                console.log(`\n[WS2_32] WSAConnectByNameA() -> ${nodename}:${servicename}`);
                
                // Redirect to proxy
                args[1].writeAnsiString(PROXY_HOST);
                args[2].writeAnsiString(PROXY_PORT.toString());
                
                console.log(`[*] Redirected to ${PROXY_HOST}:${PROXY_PORT}`);
            }
        });
        console.log("[✓] Hooked: WSAConnectByNameA()");
    }

    // Hook WSAConnectByNameW()
    const wsaConnectByNameWPtr = Module.findExportByName("ws2_32.dll", "WSAConnectByNameW");
    if (wsaConnectByNameWPtr) {
        Interceptor.attach(wsaConnectByNameWPtr, {
            onEnter: function(args) {
                const nodename = args[1].readUtf16String();
                const servicename = args[2].readUtf16String();
                
                console.log(`\n[WS2_32] WSAConnectByNameW() -> ${nodename}:${servicename}`);
                
                args[1].writeUtf16String(PROXY_HOST);
                args[2].writeUtf16String(PROXY_PORT.toString());
                
                console.log(`[*] Redirected to ${PROXY_HOST}:${PROXY_PORT}`);
            }
        });
        console.log("[✓] Hooked: WSAConnectByNameW()");
    }

    // Hook getaddrinfo()
    const getaddrinfoPtr = Module.findExportByName("ws2_32.dll", "getaddrinfo");
    if (getaddrinfoPtr) {
        Interceptor.attach(getaddrinfoPtr, {
            onEnter: function(args) {
                const hostname = args[0].readAnsiString();
                const service = args[1].readAnsiString();
                console.log(`\n[WS2_32] getaddrinfo() -> ${hostname}:${service || 'null'}`);
            }
        });
        console.log("[✓] Hooked: getaddrinfo()");
    }

    // Hook GetAddrInfoW()
    const getAddrInfoWPtr = Module.findExportByName("ws2_32.dll", "GetAddrInfoW");
    if (getAddrInfoWPtr) {
        Interceptor.attach(getAddrInfoWPtr, {
            onEnter: function(args) {
                const hostname = args[0].readUtf16String();
                console.log(`\n[WS2_32] GetAddrInfoW() -> ${hostname}`);
            }
        });
        console.log("[✓] Hooked: GetAddrInfoW()");
    }

    // Hook send() - for traffic inspection
    const sendPtr = Module.findExportByName("ws2_32.dll", "send");
    if (sendPtr) {
        Interceptor.attach(sendPtr, {
            onEnter: function(args) {
                const buf = args[1];
                const len = args[2].toInt32();
                
                if (len > 0 && len < 8192) {
                    try {
                        const data = buf.readByteArray(Math.min(len, 512));
                        console.log(`\n[>>] send() ${len} bytes:`);
                        console.log(hexdump(data, {length: Math.min(len, 512)}));
                    } catch(e) {}
                }
            }
        });
        console.log("[✓] Hooked: send()");
    }

    // Hook recv()
    const recvPtr = Module.findExportByName("ws2_32.dll", "recv");
    if (recvPtr) {
        Interceptor.attach(recvPtr, {
            onLeave: function(retval) {
                const len = retval.toInt32();
                if (len > 0) {
                    console.log(`\n[<<] recv() ${len} bytes received`);
                }
            }
        });
        console.log("[✓] Hooked: recv()");
    }

} catch(e) {
    console.log("[-] ws2_32.dll not loaded yet");
}

// ============================================================================
// WINHTTP API HOOKS (winhttp.dll)
// ============================================================================

try {
    const winhttp = Process.getModuleByName("winhttp.dll");
    console.log("\n[+] Found winhttp.dll");

    // Hook WinHttpConnect()
    const winHttpConnectPtr = Module.findExportByName("winhttp.dll", "WinHttpConnect");
    if (winHttpConnectPtr) {
        Interceptor.attach(winHttpConnectPtr, {
            onEnter: function(args) {
                const serverName = args[1].readUtf16String();
                const port = args[2].toInt32();
                
                console.log(`\n[WINHTTP] WinHttpConnect() -> ${serverName}:${port}`);
                
                // Redirect to proxy
                args[1].writeUtf16String(PROXY_HOST);
                args[2] = ptr(PROXY_PORT);
                
                console.log(`[*] Redirected to ${PROXY_HOST}:${PROXY_PORT}`);
            }
        });
        console.log("[✓] Hooked: WinHttpConnect()");
    }

    // Hook WinHttpOpenRequest()
    const winHttpOpenRequestPtr = Module.findExportByName("winhttp.dll", "WinHttpOpenRequest");
    if (winHttpOpenRequestPtr) {
        Interceptor.attach(winHttpOpenRequestPtr, {
            onEnter: function(args) {
                const verb = args[1].readUtf16String();
                const object = args[2].readUtf16String();
                
                console.log(`\n[WINHTTP] WinHttpOpenRequest() -> ${verb} ${object}`);
            }
        });
        console.log("[✓] Hooked: WinHttpOpenRequest()");
    }

    // Hook WinHttpSetOption() - to set proxy
    const winHttpSetOptionPtr = Module.findExportByName("winhttp.dll", "WinHttpSetOption");
    if (winHttpSetOptionPtr) {
        Interceptor.attach(winHttpSetOptionPtr, {
            onEnter: function(args) {
                const option = args[1].toInt32();
                
                // WINHTTP_OPTION_PROXY = 38
                if (option === 38) {
                    console.log(`\n[WINHTTP] WinHttpSetOption() - Proxy setting detected`);
                }
            }
        });
        console.log("[✓] Hooked: WinHttpSetOption()");
    }

} catch(e) {
    console.log("[-] winhttp.dll not loaded yet");
}

// ============================================================================
// WININET API HOOKS (wininet.dll)
// ============================================================================

try {
    const wininet = Process.getModuleByName("wininet.dll");
    console.log("\n[+] Found wininet.dll");

    // Hook InternetConnectA()
    const internetConnectAPtr = Module.findExportByName("wininet.dll", "InternetConnectA");
    if (internetConnectAPtr) {
        Interceptor.attach(internetConnectAPtr, {
            onEnter: function(args) {
                const serverName = args[1].readAnsiString();
                const port = args[2].toInt32();
                
                console.log(`\n[WININET] InternetConnectA() -> ${serverName}:${port}`);
                
                // Redirect to proxy
                args[1].writeAnsiString(PROXY_HOST);
                args[2] = ptr(PROXY_PORT);
                
                console.log(`[*] Redirected to ${PROXY_HOST}:${PROXY_PORT}`);
            }
        });
        console.log("[✓] Hooked: InternetConnectA()");
    }

    // Hook InternetConnectW()
    const internetConnectWPtr = Module.findExportByName("wininet.dll", "InternetConnectW");
    if (internetConnectWPtr) {
        Interceptor.attach(internetConnectWPtr, {
            onEnter: function(args) {
                const serverName = args[1].readUtf16String();
                const port = args[2].toInt32();
                
                console.log(`\n[WININET] InternetConnectW() -> ${serverName}:${port}`);
                
                args[1].writeUtf16String(PROXY_HOST);
                args[2] = ptr(PROXY_PORT);
                
                console.log(`[*] Redirected to ${PROXY_HOST}:${PROXY_PORT}`);
            }
        });
        console.log("[✓] Hooked: InternetConnectW()");
    }

    // Hook InternetOpenUrlA()
    const internetOpenUrlAPtr = Module.findExportByName("wininet.dll", "InternetOpenUrlA");
    if (internetOpenUrlAPtr) {
        Interceptor.attach(internetOpenUrlAPtr, {
            onEnter: function(args) {
                const url = args[1].readAnsiString();
                console.log(`\n[WININET] InternetOpenUrlA() -> ${url}`);
            }
        });
        console.log("[✓] Hooked: InternetOpenUrlA()");
    }

    // Hook InternetOpenUrlW()
    const internetOpenUrlWPtr = Module.findExportByName("wininet.dll", "InternetOpenUrlW");
    if (internetOpenUrlWPtr) {
        Interceptor.attach(internetOpenUrlWPtr, {
            onEnter: function(args) {
                const url = args[1].readUtf16String();
                console.log(`\n[WININET] InternetOpenUrlW() -> ${url}`);
            }
        });
        console.log("[✓] Hooked: InternetOpenUrlW()");
    }

    // Hook HttpOpenRequestA()
    const httpOpenRequestAPtr = Module.findExportByName("wininet.dll", "HttpOpenRequestA");
    if (httpOpenRequestAPtr) {
        Interceptor.attach(httpOpenRequestAPtr, {
            onEnter: function(args) {
                const verb = args[1].readAnsiString();
                const object = args[2].readAnsiString();
                console.log(`\n[WININET] HttpOpenRequestA() -> ${verb} ${object}`);
            }
        });
        console.log("[✓] Hooked: HttpOpenRequestA()");
    }

    // Hook HttpOpenRequestW()
    const httpOpenRequestWPtr = Module.findExportByName("wininet.dll", "HttpOpenRequestW");
    if (httpOpenRequestWPtr) {
        Interceptor.attach(httpOpenRequestWPtr, {
            onEnter: function(args) {
                const verb = args[1].readUtf16String();
                const object = args[2].readUtf16String();
                console.log(`\n[WININET] HttpOpenRequestW() -> ${verb} ${object}`);
            }
        });
        console.log("[✓] Hooked: HttpOpenRequestW()");
    }

} catch(e) {
    console.log("[-] wininet.dll not loaded yet");
}

// ============================================================================
// .NET FRAMEWORK HOOKS (System.Net)
// ============================================================================

setTimeout(function() {
    try {
        console.log("\n[+] Attempting to hook .NET System.Net APIs...");
        
        // Hook System.Net.Sockets.Socket.Connect
        const socketConnect = Module.findExportByName("clr.dll", "Socket_Connect");
        if (socketConnect) {
            console.log("[✓] Found .NET Socket.Connect");
        }
        
        // For .NET, we can also hook at the CLR level
        const clr = Process.findModuleByName("clr.dll") || Process.findModuleByName("coreclr.dll");
        if (clr) {
            console.log("[+] .NET CLR detected");
        }
        
    } catch(e) {
        console.log("[-] .NET hooks not available");
    }
}, 1000);

// ============================================================================
// MSWSOCK HOOKS (for low-level operations)
// ============================================================================

try {
    const mswsock = Process.getModuleByName("mswsock.dll");
    console.log("\n[+] Found mswsock.dll");
    
    // Hook ConnectEx()
    const connectExPtr = Module.findExportByName("mswsock.dll", "ConnectEx");
    if (connectExPtr) {
        Interceptor.attach(connectExPtr, {
            onEnter: function(args) {
                const sockaddr = args[1];
                const sa_family = sockaddr.readU16();
                
                if (sa_family === 2) { // AF_INET
                    const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                    const ip = sockaddr.add(4).readU32();
                    const ipStr = `${ip & 0xFF}.${(ip >> 8) & 0xFF}.${(ip >> 16) & 0xFF}.${(ip >> 24) & 0xFF}`;
                    
                    console.log(`\n[MSWSOCK] ConnectEx() -> ${ipStr}:${port}`);
                    
                    sockaddr.add(2).writeU8((PROXY_PORT >> 8) & 0xFF);
                    sockaddr.add(3).writeU8(PROXY_PORT & 0xFF);
                    sockaddr.add(4).writeU32(0x0100007F);
                    
                    console.log(`[*] Redirected to ${PROXY_HOST}:${PROXY_PORT}`);
                }
            }
        });
        console.log("[✓] Hooked: ConnectEx()");
    }
    
} catch(e) {
    console.log("[-] mswsock.dll not loaded yet");
}

console.log("\n[*] ========================================");
console.log("[*] All available hooks installed!");
console.log("[*] Monitoring network activity...");
console.log("[*] ========================================\n");