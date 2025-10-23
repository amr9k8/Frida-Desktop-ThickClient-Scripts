// Frida script to intercept all file write operations
// Usage: frida -l script.js <target.exe> or frida -p <PID> -l script.js

// NOTE: renamed local hexdump helper to avoid conflict with Frida's global `hexdump`.
console.log("[*] Starting File Write Monitor");
console.log("[*] Hooking file I/O operations\n");

// Store file handles to track filenames
const fileHandles = new Map();

// Helper function to dump hex data (renamed from hexdump -> dumpHex)
function dumpHex(buffer, length) {
    if (!buffer || length === 0) return "";
    try {
        const bytes = Memory.readByteArray(buffer, Math.min(length, 2048)); // Increased to 2KB
        return dumpHexArray(bytes);
    } catch (e) {
        return "[Error reading memory]";
    }
}

function dumpHexArray(byteArray) {
    const u8 = new Uint8Array(byteArray);
    let result = "\n";
    for (let i = 0; i < Math.min(u8.length, 512); i += 16) {
        const chunk = u8.slice(i, Math.min(i + 16, u8.length));
        const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
        const ascii = Array.from(chunk).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
        result += `  ${i.toString(16).padStart(8, '0')}: ${hex.padEnd(48, ' ')} | ${ascii}\n`;
    }
    if (u8.length > 512) {
        result += `  ... (${u8.length - 512} more bytes)\n`;
    }
    return result;
}

// Helper to extract ASCII/UTF-8 text
function tryReadString(buffer, length) {
    try {
        const data = Memory.readByteArray(buffer, Math.min(length, 2048));
        const u8 = new Uint8Array(data);
        let str = "";
        for (let i = 0; i < u8.length; i++) {
            if (u8[i] >= 32 && u8[i] <= 126) {
                str += String.fromCharCode(u8[i]);
            } else if (u8[i] === 10 || u8[i] === 13 || u8[i] === 9) {
                str += String.fromCharCode(u8[i]);
            } else {
                str += ".";
            }
        }
        if (length > 2048) {
            str += `\n... (${length - 2048} more bytes)`;
        }
        return str;
    } catch (e) {
        return "[Error reading string]";
    }
}

// Hook CreateFileW (Unicode version)
try {
    const createFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
    if (createFileW) {
        Interceptor.attach(createFileW, {
            onEnter: function(args) {
                try {
                    this.filename = Memory.readUtf16String(args[0]);
                    this.access = args[1].toInt32();
                    this.disposition = args[4].toInt32();
                } catch (e) {
                    this.filename = "[Error reading filename]";
                }
            },
            onLeave: function(retval) {
                const handle = retval.toInt32();
                if (handle !== -1 && handle !== 0) {
                    // Check if file opened for writing (GENERIC_WRITE = 0x40000000)
                    if ((this.access & 0x40000000) !== 0 || (this.access & 0x10000000) !== 0) {
                        fileHandles.set(handle, this.filename);
                        console.log("\n[FILE OPEN] Handle:", "0x" + handle.toString(16));
                        console.log("  Filename:", this.filename);
                        console.log("  Access:", "0x" + this.access.toString(16));
                        console.log("  Disposition:", this.disposition);
                    }
                }
            }
        });
        console.log("[+] Hooked CreateFileW()");
    }
} catch (e) {
    console.log("[-] Error hooking CreateFileW:", e);
}

// Hook CreateFileA (ANSI version)
try {
    const createFileA = Module.findExportByName("kernel32.dll", "CreateFileA");
    if (createFileA) {
        Interceptor.attach(createFileA, {
            onEnter: function(args) {
                try {
                    this.filename = Memory.readAnsiString(args[0]);
                    this.access = args[1].toInt32();
                    this.disposition = args[4].toInt32();
                } catch (e) {
                    this.filename = "[Error reading filename]";
                }
            },
            onLeave: function(retval) {
                const handle = retval.toInt32();
                if (handle !== -1 && handle !== 0) {
                    if ((this.access & 0x40000000) !== 0 || (this.access & 0x10000000) !== 0) {
                        fileHandles.set(handle, this.filename);
                        console.log("\n[FILE OPEN] Handle:", "0x" + handle.toString(16));
                        console.log("  Filename:", this.filename);
                        console.log("  Access:", "0x" + this.access.toString(16));
                    }
                }
            }
        });
        console.log("[+] Hooked CreateFileA()");
    }
} catch (e) {
    console.log("[-] Error hooking CreateFileA:", e);
}

// Hook WriteFile
try {
    const writeFile = Module.findExportByName("kernel32.dll", "WriteFile");
    if (writeFile) {
        Interceptor.attach(writeFile, {
            onEnter: function(args) {
                this.handle = args[0].toInt32();
                this.buffer = args[1];
                this.size = args[2].toInt32();
                this.bytesWritten = args[3];
                
                const filename = fileHandles.get(this.handle) || "Unknown";
                
                console.log("\n" + "=".repeat(80));
                console.log("[WRITE FILE]");
                console.log("  Handle:", "0x" + this.handle.toString(16));
                console.log("  Filename:", filename);
                console.log("  Size:", this.size, "bytes");
                
                if (this.size > 0) {
                    console.log("\n[HEX DUMP]");
                    console.log(dumpHex(this.buffer, this.size));
                    
                    console.log("\n[ASCII/TEXT]");
                    console.log(tryReadString(this.buffer, this.size));
                }
                console.log("=".repeat(80));
            },
            onLeave: function(retval) {
                if (this.bytesWritten && !this.bytesWritten.isNull()) {
                    try {
                        const written = Memory.readU32(this.bytesWritten);
                        console.log("[WRITE RESULT] Bytes written:", written);
                    } catch (e) {}
                }
            }
        });
        console.log("[+] Hooked WriteFile()");
    }
} catch (e) {
    console.log("[-] Error hooking WriteFile:", e);
}

// Hook fwrite (C runtime)
try {
    const msvcrt = Process.findModuleByName("msvcrt.dll") || 
                   Process.findModuleByName("ucrtbase.dll");
    
    if (msvcrt) {
        const fwrite = Module.findExportByName(msvcrt.name, "fwrite");
        if (fwrite) {
            Interceptor.attach(fwrite, {
                onEnter: function(args) {
                    this.buffer = args[0];
                    this.size = args[1].toInt32();
                    this.count = args[2].toInt32();
                    this.stream = args[3];
                    this.totalSize = this.size * this.count;
                    
                    console.log("\n" + "=".repeat(80));
                    console.log("[FWRITE]");
                    console.log("  Stream:", this.stream);
                    console.log("  Size:", this.totalSize, "bytes");
                    
                    if (this.totalSize > 0) {
                        console.log("\n[HEX DUMP]");
                        console.log(dumpHex(this.buffer, this.totalSize));
                        
                        console.log("\n[ASCII/TEXT]");
                        console.log(tryReadString(this.buffer, this.totalSize));
                    }
                    console.log("=".repeat(80));
                }
            });
            console.log("[+] Hooked fwrite() in", msvcrt.name);
        }

        // Hook fprintf
        const fprintf = Module.findExportByName(msvcrt.name, "fprintf");
        if (fprintf) {
            Interceptor.attach(fprintf, {
                onEnter: function(args) {
                    try {
                        const format = Memory.readAnsiString(args[1]);
                        console.log("\n[FPRINTF]");
                        console.log("  Format:", format);
                    } catch (e) {}
                }
            });
            console.log("[+] Hooked fprintf() in", msvcrt.name);
        }

        // Hook fputs
        const fputs = Module.findExportByName(msvcrt.name, "fputs");
        if (fputs) {
            Interceptor.attach(fputs, {
                onEnter: function(args) {
                    try {
                        const str = Memory.readAnsiString(args[0]);
                        console.log("\n[FPUTS]");
                        console.log("  String:", str);
                    } catch (e) {}
                }
            });
            console.log("[+] Hooked fputs() in", msvcrt.name);
        }
    }
} catch (e) {
    console.log("[-] Error hooking C runtime functions:", e);
}

// Hook CloseHandle to clean up our tracking
try {
    const closeHandle = Module.findExportByName("kernel32.dll", "CloseHandle");
    if (closeHandle) {
        Interceptor.attach(closeHandle, {
            onEnter: function(args) {
                const handle = args[0].toInt32();
                if (fileHandles.has(handle)) {
                    const filename = fileHandles.get(handle);
                    console.log("\n[FILE CLOSE] Handle:", "0x" + handle.toString(16));
                    console.log("  Filename:", filename);
                    fileHandles.delete(handle);
                }
            }
        });
        console.log("[+] Hooked CloseHandle()");
    }
} catch (e) {
    console.log("[-] Error hooking CloseHandle:", e);
}

// Hook NtWriteFile (Native API)
try {
    const ntdll = Process.findModuleByName("ntdll.dll");
    if (ntdll) {
        const ntWriteFile = Module.findExportByName("ntdll.dll", "NtWriteFile");
        if (ntWriteFile) {
            Interceptor.attach(ntWriteFile, {
                onEnter: function(args) {
                    this.handle = args[0].toInt32();
                    // args[5] is buffer, args[6] is length
                    this.buffer = args[5];
                    this.length = args[6].toInt32();
                    
                    const filename = fileHandles.get(this.handle) || "Unknown";
                    
                    console.log("\n" + "=".repeat(80));
                    console.log("[NT WRITE FILE]");
                    console.log("  Handle:", "0x" + this.handle.toString(16));
                    console.log("  Filename:", filename);
                    console.log("  Size:", this.length, "bytes");
                    
                    if (this.length > 0 && !this.buffer.isNull()) {
                        console.log("\n[HEX DUMP]");
                        console.log(dumpHex(this.buffer, this.length));
                        
                        console.log("\n[ASCII/TEXT]");
                        console.log(tryReadString(this.buffer, this.length));
                    }
                    console.log("=".repeat(80));
                }
            });
            console.log("[+] Hooked NtWriteFile()");
        }
    }
} catch (e) {
    console.log("[-] Error hooking NtWriteFile:", e);
}

// Hook file mapping (memory-mapped files)
try {
    const mapViewOfFile = Module.findExportByName("kernel32.dll", "MapViewOfFile");
    if (mapViewOfFile) {
        Interceptor.attach(mapViewOfFile, {
            onEnter: function(args) {
                this.handle = args[0].toInt32();
                this.access = args[1].toInt32();
            },
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    console.log("\n[MEMORY MAPPED FILE]");
                    console.log("  Handle:", "0x" + this.handle.toString(16));
                    console.log("  Mapped at:", retval);
                    console.log("  Access:", "0x" + this.access.toString(16));
                }
            }
        });
        console.log("[+] Hooked MapViewOfFile()");
    }
} catch (e) {
    console.log("[-] Error hooking MapViewOfFile:", e);
}

console.log("\n[*] All hooks installed. Monitoring file writes...\n");
