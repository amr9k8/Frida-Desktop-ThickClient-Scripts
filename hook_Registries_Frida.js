// Frida script to intercept all registry operations
// Usage: frida -l script.js <target.exe> or frida -p <PID> -l script.js

console.log("[*] Starting Registry Monitor");
console.log("[*] Hooking registry operations\n");

// Store registry handles to track key names
const regHandles = new Map();

// Registry root key names
const rootKeys = {
    0x80000000: "HKEY_CLASSES_ROOT",
    0x80000001: "HKEY_CURRENT_USER",
    0x80000002: "HKEY_LOCAL_MACHINE",
    0x80000003: "HKEY_USERS",
    0x80000004: "HKEY_PERFORMANCE_DATA",
    0x80000005: "HKEY_CURRENT_CONFIG",
    0x80000006: "HKEY_DYN_DATA"
};

// Registry value types
const regTypes = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD"
};

// Helper function to get root key name
function getRootKeyName(handle) {
    const handleValue = handle.toInt32();
    return rootKeys[handleValue] || rootKeys[handleValue & 0xFFFFFFFF] || "UNKNOWN_ROOT";
}

// Helper function to dump hex data
function hexdump_local(buffer, length) {
    if (!buffer || length === 0) return "";
    try {
        const bytes = Memory.readByteArray(buffer, Math.min(length, 1024));
        return hexdump_array(bytes);
    } catch (e) {
        return "[Error reading memory]";
    }
}

function hexdump_array(byteArray) {
    const u8 = new Uint8Array(byteArray);
    let result = "\n";
    for (let i = 0; i < Math.min(u8.length, 256); i += 16) {
        const chunk = u8.slice(i, Math.min(i + 16, u8.length));
        const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
        const ascii = Array.from(chunk).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
        result += `    ${i.toString(16).padStart(4, '0')}: ${hex.padEnd(48, ' ')} | ${ascii}\n`;
    }
    if (u8.length > 256) {
        result += `    ... (${u8.length - 256} more bytes)\n`;
    }
    return result;
}

// Helper to read registry value data
function readRegistryValue(type, data, size) {
    if (!data || data.isNull() || size <= 0) {
        return "[NULL or empty]";
    }

    try {
        switch (type) {
            case 1: // REG_SZ
            case 2: // REG_EXPAND_SZ
                try {
                    return Memory.readUtf16String(data);
                } catch (e) {
                    return Memory.readAnsiString(data);
                }
            
            case 4: // REG_DWORD
                if (size >= 4) {
                    const value = Memory.readU32(data);
                    return `0x${value.toString(16)} (${value})`;
                }
                return "[Invalid DWORD]";
            
            case 11: // REG_QWORD
                if (size >= 8) {
                    const low = Memory.readU32(data);
                    const high = Memory.readU32(data.add(4));
                    return `0x${high.toString(16)}${low.toString(16).padStart(8, '0')}`;
                }
                return "[Invalid QWORD]";
            
            case 7: // REG_MULTI_SZ
                try {
                    let result = [];
                    let offset = 0;
                    while (offset < size - 2) {
                        const str = Memory.readUtf16String(data.add(offset));
                        if (str.length === 0) break;
                        result.push(str);
                        offset += (str.length + 1) * 2;
                    }
                    return result.join(", ");
                } catch (e) {
                    return "[Error reading MULTI_SZ]";
                }
            
            case 3: // REG_BINARY
            default:
                return hexdump_local(data, size);
        }
    } catch (e) {
        return `[Error reading value: ${e}]`;
    }
}

// Hook RegOpenKeyExW
try {
    const regOpenKeyExW = Module.findExportByName("advapi32.dll", "RegOpenKeyExW");
    if (regOpenKeyExW) {
        Interceptor.attach(regOpenKeyExW, {
            onEnter: function(args) {
                this.rootKey = args[0];
                try {
                    this.subKey = Memory.readUtf16String(args[1]);
                } catch (e) {
                    this.subKey = "[Error reading key]";
                }
                this.access = args[2].toInt32();
                this.resultHandle = args[4];
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0 && !this.resultHandle.isNull()) {
                    try {
                        const handle = Memory.readPointer(this.resultHandle);
                        const rootName = getRootKeyName(this.rootKey);
                        const fullPath = `${rootName}\\${this.subKey}`;
                        regHandles.set(handle.toString(), fullPath);
                        
                        console.log("\n[REG OPEN KEY]");
                        console.log("  Path:", fullPath);
                        console.log("  Handle:", handle);
                        console.log("  Access:", "0x" + this.access.toString(16));
                    } catch (e) {}
                }
            }
        });
        console.log("[+] Hooked RegOpenKeyExW()");
    }
} catch (e) {
    console.log("[-] Error hooking RegOpenKeyExW:", e);
}

// Hook RegOpenKeyExA
try {
    const regOpenKeyExA = Module.findExportByName("advapi32.dll", "RegOpenKeyExA");
    if (regOpenKeyExA) {
        Interceptor.attach(regOpenKeyExA, {
            onEnter: function(args) {
                this.rootKey = args[0];
                try {
                    this.subKey = Memory.readAnsiString(args[1]);
                } catch (e) {
                    this.subKey = "[Error reading key]";
                }
                this.access = args[2].toInt32();
                this.resultHandle = args[4];
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0 && !this.resultHandle.isNull()) {
                    try {
                        const handle = Memory.readPointer(this.resultHandle);
                        const rootName = getRootKeyName(this.rootKey);
                        const fullPath = `${rootName}\\${this.subKey}`;
                        regHandles.set(handle.toString(), fullPath);
                        
                        console.log("\n[REG OPEN KEY]");
                        console.log("  Path:", fullPath);
                        console.log("  Handle:", handle);
                    } catch (e) {}
                }
            }
        });
        console.log("[+] Hooked RegOpenKeyExA()");
    }
} catch (e) {
    console.log("[-] Error hooking RegOpenKeyExA:", e);
}

// Hook RegCreateKeyExW
try {
    const regCreateKeyExW = Module.findExportByName("advapi32.dll", "RegCreateKeyExW");
    if (regCreateKeyExW) {
        Interceptor.attach(regCreateKeyExW, {
            onEnter: function(args) {
                this.rootKey = args[0];
                try {
                    this.subKey = Memory.readUtf16String(args[1]);
                } catch (e) {
                    this.subKey = "[Error reading key]";
                }
                this.resultHandle = args[7];
                this.disposition = args[8];
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0 && !this.resultHandle.isNull()) {
                    try {
                        const handle = Memory.readPointer(this.resultHandle);
                        const rootName = getRootKeyName(this.rootKey);
                        const fullPath = `${rootName}\\${this.subKey}`;
                        regHandles.set(handle.toString(), fullPath);
                        
                        let dispStr = "UNKNOWN";
                        if (!this.disposition.isNull()) {
                            const disp = Memory.readU32(this.disposition);
                            dispStr = disp === 1 ? "CREATED_NEW_KEY" : "OPENED_EXISTING_KEY";
                        }
                        
                        console.log("\n" + "=".repeat(80));
                        console.log("[REG CREATE KEY]");
                        console.log("  Path:", fullPath);
                        console.log("  Handle:", handle);
                        console.log("  Disposition:", dispStr);
                        console.log("=".repeat(80));
                    } catch (e) {}
                }
            }
        });
        console.log("[+] Hooked RegCreateKeyExW()");
    }
} catch (e) {
    console.log("[-] Error hooking RegCreateKeyExW:", e);
}

// Hook RegCreateKeyExA
try {
    const regCreateKeyExA = Module.findExportByName("advapi32.dll", "RegCreateKeyExA");
    if (regCreateKeyExA) {
        Interceptor.attach(regCreateKeyExA, {
            onEnter: function(args) {
                this.rootKey = args[0];
                try {
                    this.subKey = Memory.readAnsiString(args[1]);
                } catch (e) {
                    this.subKey = "[Error reading key]";
                }
                this.resultHandle = args[7];
                this.disposition = args[8];
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0 && !this.resultHandle.isNull()) {
                    try {
                        const handle = Memory.readPointer(this.resultHandle);
                        const rootName = getRootKeyName(this.rootKey);
                        const fullPath = `${rootName}\\${this.subKey}`;
                        regHandles.set(handle.toString(), fullPath);
                        
                        let dispStr = "UNKNOWN";
                        if (!this.disposition.isNull()) {
                            const disp = Memory.readU32(this.disposition);
                            dispStr = disp === 1 ? "CREATED_NEW_KEY" : "OPENED_EXISTING_KEY";
                        }
                        
                        console.log("\n" + "=".repeat(80));
                        console.log("[REG CREATE KEY]");
                        console.log("  Path:", fullPath);
                        console.log("  Handle:", handle);
                        console.log("  Disposition:", dispStr);
                        console.log("=".repeat(80));
                    } catch (e) {}
                }
            }
        });
        console.log("[+] Hooked RegCreateKeyExA()");
    }
} catch (e) {
    console.log("[-] Error hooking RegCreateKeyExA:", e);
}

// Hook RegSetValueExW
try {
    const regSetValueExW = Module.findExportByName("advapi32.dll", "RegSetValueExW");
    if (regSetValueExW) {
        Interceptor.attach(regSetValueExW, {
            onEnter: function(args) {
                this.handle = args[0];
                try {
                    this.valueName = args[1].isNull() ? "(Default)" : Memory.readUtf16String(args[1]);
                } catch (e) {
                    this.valueName = "[Error reading value name]";
                }
                this.type = args[3].toInt32();
                this.data = args[4];
                this.size = args[5].toInt32();
                
                const keyPath = regHandles.get(this.handle.toString()) || "UNKNOWN_KEY";
                const typeStr = regTypes[this.type] || `UNKNOWN(${this.type})`;
                
                console.log("\n" + "=".repeat(80));
                console.log("[REG SET VALUE]");
                console.log("  Key:", keyPath);
                console.log("  Value Name:", this.valueName);
                console.log("  Type:", typeStr);
                console.log("  Size:", this.size, "bytes");
                console.log("  Data:", readRegistryValue(this.type, this.data, this.size));
                console.log("=".repeat(80));
            }
        });
        console.log("[+] Hooked RegSetValueExW()");
    }
} catch (e) {
    console.log("[-] Error hooking RegSetValueExW:", e);
}

// Hook RegSetValueExA
try {
    const regSetValueExA = Module.findExportByName("advapi32.dll", "RegSetValueExA");
    if (regSetValueExA) {
        Interceptor.attach(regSetValueExA, {
            onEnter: function(args) {
                this.handle = args[0];
                try {
                    this.valueName = args[1].isNull() ? "(Default)" : Memory.readAnsiString(args[1]);
                } catch (e) {
                    this.valueName = "[Error reading value name]";
                }
                this.type = args[3].toInt32();
                this.data = args[4];
                this.size = args[5].toInt32();
                
                const keyPath = regHandles.get(this.handle.toString()) || "UNKNOWN_KEY";
                const typeStr = regTypes[this.type] || `UNKNOWN(${this.type})`;
                
                console.log("\n" + "=".repeat(80));
                console.log("[REG SET VALUE]");
                console.log("  Key:", keyPath);
                console.log("  Value Name:", this.valueName);
                console.log("  Type:", typeStr);
                console.log("  Size:", this.size, "bytes");
                console.log("  Data:", readRegistryValue(this.type, this.data, this.size));
                console.log("=".repeat(80));
            }
        });
        console.log("[+] Hooked RegSetValueExA()");
    }
} catch (e) {
    console.log("[-] Error hooking RegSetValueExA:", e);
}

// Hook RegDeleteValueW
try {
    const regDeleteValueW = Module.findExportByName("advapi32.dll", "RegDeleteValueW");
    if (regDeleteValueW) {
        Interceptor.attach(regDeleteValueW, {
            onEnter: function(args) {
                const handle = args[0];
                try {
                    this.valueName = args[1].isNull() ? "(Default)" : Memory.readUtf16String(args[1]);
                } catch (e) {
                    this.valueName = "[Error reading value name]";
                }
                
                const keyPath = regHandles.get(handle.toString()) || "UNKNOWN_KEY";
                
                console.log("\n" + "=".repeat(80));
                console.log("[REG DELETE VALUE]");
                console.log("  Key:", keyPath);
                console.log("  Value Name:", this.valueName);
                console.log("=".repeat(80));
            }
        });
        console.log("[+] Hooked RegDeleteValueW()");
    }
} catch (e) {
    console.log("[-] Error hooking RegDeleteValueW:", e);
}

// Hook RegDeleteValueA
try {
    const regDeleteValueA = Module.findExportByName("advapi32.dll", "RegDeleteValueA");
    if (regDeleteValueA) {
        Interceptor.attach(regDeleteValueA, {
            onEnter: function(args) {
                const handle = args[0];
                try {
                    this.valueName = args[1].isNull() ? "(Default)" : Memory.readAnsiString(args[1]);
                } catch (e) {
                    this.valueName = "[Error reading value name]";
                }
                
                const keyPath = regHandles.get(handle.toString()) || "UNKNOWN_KEY";
                
                console.log("\n" + "=".repeat(80));
                console.log("[REG DELETE VALUE]");
                console.log("  Key:", keyPath);
                console.log("  Value Name:", this.valueName);
                console.log("=".repeat(80));
            }
        });
        console.log("[+] Hooked RegDeleteValueA()");
    }
} catch (e) {
    console.log("[-] Error hooking RegDeleteValueA:", e);
}

// Hook RegDeleteKeyW
try {
    const regDeleteKeyW = Module.findExportByName("advapi32.dll", "RegDeleteKeyW");
    if (regDeleteKeyW) {
        Interceptor.attach(regDeleteKeyW, {
            onEnter: function(args) {
                const handle = args[0];
                try {
                    this.subKey = Memory.readUtf16String(args[1]);
                } catch (e) {
                    this.subKey = "[Error reading key]";
                }
                
                const keyPath = regHandles.get(handle.toString()) || getRootKeyName(handle);
                
                console.log("\n" + "=".repeat(80));
                console.log("[REG DELETE KEY]");
                console.log("  Key:", `${keyPath}\\${this.subKey}`);
                console.log("=".repeat(80));
            }
        });
        console.log("[+] Hooked RegDeleteKeyW()");
    }
} catch (e) {
    console.log("[-] Error hooking RegDeleteKeyW:", e);
}

// Hook RegDeleteKeyA
try {
    const regDeleteKeyA = Module.findExportByName("advapi32.dll", "RegDeleteKeyA");
    if (regDeleteKeyA) {
        Interceptor.attach(regDeleteKeyA, {
            onEnter: function(args) {
                const handle = args[0];
                try {
                    this.subKey = Memory.readAnsiString(args[1]);
                } catch (e) {
                    this.subKey = "[Error reading key]";
                }
                
                const keyPath = regHandles.get(handle.toString()) || getRootKeyName(handle);
                
                console.log("\n" + "=".repeat(80));
                console.log("[REG DELETE KEY]");
                console.log("  Key:", `${keyPath}\\${this.subKey}`);
                console.log("=".repeat(80));
            }
        });
        console.log("[+] Hooked RegDeleteKeyA()");
    }
} catch (e) {
    console.log("[-] Error hooking RegDeleteKeyA:", e);
}

// Hook RegCloseKey
try {
    const regCloseKey = Module.findExportByName("advapi32.dll", "RegCloseKey");
    if (regCloseKey) {
        Interceptor.attach(regCloseKey, {
            onEnter: function(args) {
                const handle = args[0];
                const handleStr = handle.toString();
                if (regHandles.has(handleStr)) {
                    const keyPath = regHandles.get(handleStr);
                    console.log("\n[REG CLOSE KEY]");
                    console.log("  Key:", keyPath);
                    console.log("  Handle:", handle);
                    regHandles.delete(handleStr);
                }
            }
        });
        console.log("[+] Hooked RegCloseKey()");
    }
} catch (e) {
    console.log("[-] Error hooking RegCloseKey:", e);
}

// Hook NtSetValueKey (Native API)
try {
    const ntSetValueKey = Module.findExportByName("ntdll.dll", "NtSetValueKey");
    if (ntSetValueKey) {
        Interceptor.attach(ntSetValueKey, {
            onEnter: function(args) {
                const handle = args[0];
                try {
                    // UNICODE_STRING structure
                    const namePtr = args[1];
                    const nameLen = Memory.readU16(namePtr);
                    const nameBuffer = Memory.readPointer(namePtr.add(Process.pointerSize === 8 ? 8 : 4));
                    this.valueName = Memory.readUtf16String(nameBuffer, nameLen / 2);
                } catch (e) {
                    this.valueName = "[Error reading value name]";
                }
                
                this.type = args[3].toInt32();
                this.data = args[4];
                this.size = args[5].toInt32();
                
                const keyPath = regHandles.get(handle.toString()) || "UNKNOWN_KEY";
                const typeStr = regTypes[this.type] || `UNKNOWN(${this.type})`;
                
                console.log("\n" + "=".repeat(80));
                console.log("[NT SET VALUE KEY]");
                console.log("  Key:", keyPath);
                console.log("  Value Name:", this.valueName);
                console.log("  Type:", typeStr);
                console.log("  Size:", this.size, "bytes");
                console.log("  Data:", readRegistryValue(this.type, this.data, this.size));
                console.log("=".repeat(80));
            }
        });
        console.log("[+] Hooked NtSetValueKey()");
    }
} catch (e) {
    console.log("[-] Error hooking NtSetValueKey:", e);
}

console.log("\n[*] All hooks installed. Monitoring registry operations...\n");