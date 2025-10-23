// Frida script to intercept cryptographic operations and secret decryption
// Usage: frida -l script.js <target.exe> or frida -p <PID> -l script.js

console.log("[*] Starting Crypto/Decryption Monitor");
console.log("[*] Hooking cryptographic functions\n");

// Helper function to dump hex data
function hexdump_local(buffer, length, maxBytes = 512) {
    if (!buffer || length === 0) return "";
    try {
        const bytes = Memory.readByteArray(buffer, Math.min(length, maxBytes));
        return hexdump_array(bytes, length > maxBytes);
    } catch (e) {
        return "[Error reading memory]";
    }
}

function hexdump_array(byteArray, truncated = false) {
    const u8 = new Uint8Array(byteArray);
    let result = "\n";
    for (let i = 0; i < u8.length; i += 16) {
        const chunk = u8.slice(i, Math.min(i + 16, u8.length));
        const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
        const ascii = Array.from(chunk).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
        result += `    ${i.toString(16).padStart(4, '0')}: ${hex.padEnd(48, ' ')} | ${ascii}\n`;
    }
    if (truncated) {
        result += `    ... (truncated, showing first ${u8.length} bytes)\n`;
    }
    return result;
}

// Helper to try reading as string
function tryReadAsString(buffer, length) {
    if (!buffer || length === 0) return null;
    try {
        const data = Memory.readByteArray(buffer, Math.min(length, 1024));
        const u8 = new Uint8Array(data);
        
        // Check if it's printable ASCII/UTF-8
        let printable = 0;
        for (let i = 0; i < u8.length; i++) {
            if ((u8[i] >= 32 && u8[i] <= 126) || u8[i] === 10 || u8[i] === 13 || u8[i] === 9) {
                printable++;
            }
        }
        
        // If >80% printable, try to show as string
        if (printable / u8.length > 0.8) {
            let str = "";
            for (let i = 0; i < u8.length; i++) {
                if (u8[i] >= 32 && u8[i] <= 126) {
                    str += String.fromCharCode(u8[i]);
                } else if (u8[i] === 10) {
                    str += "\\n";
                } else if (u8[i] === 13) {
                    str += "\\r";
                } else if (u8[i] === 9) {
                    str += "\\t";
                } else {
                    str += `.`;
                }
            }
            return str;
        }
        
        // Try UTF-16
        try {
            const utf16 = Memory.readUtf16String(buffer, Math.min(length / 2, 512));
            if (utf16 && utf16.length > 0) {
                return utf16;
            }
        } catch (e) {}
        
        return null;
    } catch (e) {
        return null;
    }
}

// Hook Windows CryptoAPI - CryptDecrypt
try {
    const cryptDecrypt = Module.findExportByName("advapi32.dll", "CryptDecrypt");
    if (cryptDecrypt) {
        Interceptor.attach(cryptDecrypt, {
            onEnter: function(args) {
                this.hKey = args[0];
                this.hHash = args[1];
                this.final = args[2].toInt32();
                this.flags = args[3].toInt32();
                this.pbData = args[4];
                this.pdwDataLen = args[5];
                
                try {
                    this.dataLen = Memory.readU32(this.pdwDataLen);
                    console.log("\n" + "=".repeat(80));
                    console.log("[CRYPTOAPI] CryptDecrypt - BEFORE");
                    console.log("  Key Handle:", this.hKey);
                    console.log("  Data Length:", this.dataLen, "bytes");
                    console.log("  Final:", this.final ? "TRUE" : "FALSE");
                    console.log("  Encrypted Data:", hexdump_local(this.pbData, this.dataLen));
                } catch (e) {
                    console.log("[CRYPTOAPI] CryptDecrypt - Error reading input:", e);
                }
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) { // Success
                    try {
                        const decryptedLen = Memory.readU32(this.pdwDataLen);
                        console.log("\n[CRYPTOAPI] CryptDecrypt - AFTER (DECRYPTED!)");
                        console.log("  Decrypted Length:", decryptedLen, "bytes");
                        console.log("  Decrypted Data:", hexdump_local(this.pbData, decryptedLen));
                        
                        const str = tryReadAsString(this.pbData, decryptedLen);
                        if (str) {
                            console.log("  [DECRYPTED STRING]:", str);
                        }
                        console.log("=".repeat(80));
                    } catch (e) {
                        console.log("  Error reading decrypted data:", e);
                    }
                }
            }
        });
        console.log("[+] Hooked CryptDecrypt()");
    }
} catch (e) {
    console.log("[-] Error hooking CryptDecrypt:", e);
}

// Hook Windows CryptoAPI - CryptEncrypt (to see what's being encrypted)
try {
    const cryptEncrypt = Module.findExportByName("advapi32.dll", "CryptEncrypt");
    if (cryptEncrypt) {
        Interceptor.attach(cryptEncrypt, {
            onEnter: function(args) {
                this.pbData = args[4];
                this.pdwDataLen = args[5];
                
                try {
                    this.dataLen = Memory.readU32(this.pdwDataLen);
                    console.log("\n" + "=".repeat(80));
                    console.log("[CRYPTOAPI] CryptEncrypt - PLAINTEXT");
                    console.log("  Data Length:", this.dataLen, "bytes");
                    console.log("  Plaintext Data:", hexdump_local(this.pbData, this.dataLen));
                    
                    const str = tryReadAsString(this.pbData, this.dataLen);
                    if (str) {
                        console.log("  [PLAINTEXT STRING]:", str);
                    }
                    console.log("=".repeat(80));
                } catch (e) {}
            }
        });
        console.log("[+] Hooked CryptEncrypt()");
    }
} catch (e) {}

// Hook BCrypt (Modern Windows Crypto) - BCryptDecrypt
try {
    const bcryptDecrypt = Module.findExportByName("bcrypt.dll", "BCryptDecrypt");
    if (bcryptDecrypt) {
        Interceptor.attach(bcryptDecrypt, {
            onEnter: function(args) {
                this.hKey = args[0];
                this.pbInput = args[1];
                this.cbInput = args[2].toInt32();
                this.pbOutput = args[5];
                this.cbOutput = args[6].toInt32();
                this.pcbResult = args[7];
                
                console.log("\n" + "=".repeat(80));
                console.log("[BCRYPT] BCryptDecrypt - BEFORE");
                console.log("  Key Handle:", this.hKey);
                console.log("  Input Length:", this.cbInput, "bytes");
                console.log("  Encrypted Data:", hexdump_local(this.pbInput, this.cbInput));
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0) { // NT_SUCCESS
                    try {
                        const resultLen = Memory.readU32(this.pcbResult);
                        console.log("\n[BCRYPT] BCryptDecrypt - AFTER (DECRYPTED!)");
                        console.log("  Decrypted Length:", resultLen, "bytes");
                        console.log("  Decrypted Data:", hexdump_local(this.pbOutput, resultLen));
                        
                        const str = tryReadAsString(this.pbOutput, resultLen);
                        if (str) {
                            console.log("  [DECRYPTED STRING]:", str);
                        }
                        console.log("=".repeat(80));
                    } catch (e) {}
                }
            }
        });
        console.log("[+] Hooked BCryptDecrypt()");
    }
} catch (e) {}

// Hook BCryptEncrypt
try {
    const bcryptEncrypt = Module.findExportByName("bcrypt.dll", "BCryptEncrypt");
    if (bcryptEncrypt) {
        Interceptor.attach(bcryptEncrypt, {
            onEnter: function(args) {
                this.pbInput = args[1];
                this.cbInput = args[2].toInt32();
                
                console.log("\n" + "=".repeat(80));
                console.log("[BCRYPT] BCryptEncrypt - PLAINTEXT");
                console.log("  Input Length:", this.cbInput, "bytes");
                console.log("  Plaintext Data:", hexdump_local(this.pbInput, this.cbInput));
                
                const str = tryReadAsString(this.pbInput, this.cbInput);
                if (str) {
                    console.log("  [PLAINTEXT STRING]:", str);
                }
                console.log("=".repeat(80));
            }
        });
        console.log("[+] Hooked BCryptEncrypt()");
    }
} catch (e) {}

// Hook OpenSSL functions if present
const opensslModules = Process.enumerateModules().filter(m => 
    m.name.toLowerCase().includes('ssl') || 
    m.name.toLowerCase().includes('crypto') ||
    m.name.toLowerCase().includes('libeay')
);

opensslModules.forEach(module => {
    console.log("[*] Found OpenSSL/Crypto module:", module.name);
    
    // Hook AES_decrypt
    try {
        const aesDecrypt = Module.findExportByName(module.name, "AES_decrypt");
        if (aesDecrypt) {
            Interceptor.attach(aesDecrypt, {
                onEnter: function(args) {
                    this.input = args[0];
                    this.output = args[1];
                    
                    console.log("\n" + "=".repeat(80));
                    console.log("[OPENSSL] AES_decrypt");
                    console.log("  Encrypted (16 bytes):", hexdump_local(this.input, 16));
                },
                onLeave: function(retval) {
                    console.log("  Decrypted (16 bytes):", hexdump_local(this.output, 16));
                    const str = tryReadAsString(this.output, 16);
                    if (str) {
                        console.log("  [DECRYPTED]:", str);
                    }
                    console.log("=".repeat(80));
                }
            });
            console.log("[+] Hooked AES_decrypt in", module.name);
        }
    } catch (e) {}
    
    // Hook EVP_DecryptFinal_ex
    try {
        const evpDecryptFinal = Module.findExportByName(module.name, "EVP_DecryptFinal_ex");
        if (evpDecryptFinal) {
            Interceptor.attach(evpDecryptFinal, {
                onEnter: function(args) {
                    this.ctx = args[0];
                    this.out = args[1];
                    this.outl = args[2];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 1) { // Success
                        try {
                            const len = Memory.readInt(this.outl);
                            console.log("\n" + "=".repeat(80));
                            console.log("[OPENSSL] EVP_DecryptFinal_ex - FINAL BLOCK");
                            console.log("  Length:", len, "bytes");
                            console.log("  Decrypted:", hexdump_local(this.out, len));
                            const str = tryReadAsString(this.out, len);
                            if (str) {
                                console.log("  [DECRYPTED]:", str);
                            }
                            console.log("=".repeat(80));
                        } catch (e) {}
                    }
                }
            });
            console.log("[+] Hooked EVP_DecryptFinal_ex in", module.name);
        }
    } catch (e) {}
});

// Hook common base64 decode functions
try {
    const crypt32 = Module.findModuleByName("crypt32.dll");
    if (crypt32) {
        const cryptStringToBinary = Module.findExportByName("crypt32.dll", "CryptStringToBinaryA");
        if (cryptStringToBinary) {
            Interceptor.attach(cryptStringToBinary, {
                onEnter: function(args) {
                    try {
                        this.input = Memory.readAnsiString(args[0]);
                        this.length = args[1].toInt32();
                        this.flags = args[2].toInt32();
                        this.pbBinary = args[3];
                        this.pcbBinary = args[4];
                        
                        // CRYPT_STRING_BASE64 = 1
                        if (this.flags === 1 || this.flags === 0x00000001) {
                            console.log("\n" + "=".repeat(80));
                            console.log("[BASE64] CryptStringToBinary - DECODE");
                            console.log("  Input (Base64):", this.input.substring(0, 200));
                            if (this.input.length > 200) {
                                console.log("  ... (truncated, total length:", this.input.length, ")");
                            }
                        }
                    } catch (e) {}
                },
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0 && this.flags === 1) { // Success
                        try {
                            const decodedLen = Memory.readU32(this.pcbBinary);
                            console.log("  Decoded Length:", decodedLen, "bytes");
                            console.log("  Decoded Data:", hexdump_local(this.pbBinary, decodedLen));
                            const str = tryReadAsString(this.pbBinary, decodedLen);
                            if (str) {
                                console.log("  [DECODED STRING]:", str);
                            }
                            console.log("=".repeat(80));
                        } catch (e) {}
                    }
                }
            });
            console.log("[+] Hooked CryptStringToBinaryA() for Base64 decoding");
        }
    }
} catch (e) {}

// Hook XOR operations (common in malware)
// This hooks memxor-like patterns by monitoring memory operations
console.log("[*] Looking for XOR decryption patterns...");

// Hook common string decryption functions by scanning for XOR patterns
// We'll hook RtlMoveMemory to catch decrypted strings
try {
    const rtlMoveMemory = Module.findExportByName("ntdll.dll", "RtlMoveMemory");
    if (rtlMoveMemory) {
        let moveCount = 0;
        Interceptor.attach(rtlMoveMemory, {
            onEnter: function(args) {
                this.dest = args[0];
                this.src = args[1];
                this.size = args[2].toInt32();
                
                // Only log interesting sizes (potential strings/configs)
                if (this.size > 8 && this.size < 4096) {
                    const str = tryReadAsString(this.src, this.size);
                    if (str && str.length > 10) {
                        // Looks like a string being moved
                        moveCount++;
                        if (moveCount % 50 === 0) { // Log every 50th to avoid spam
                            console.log("\n[MEMORY MOVE] Potential decrypted string:");
                            console.log("  Size:", this.size, "bytes");
                            console.log("  String:", str.substring(0, 200));
                        }
                    }
                }
            }
        });
        console.log("[+] Hooked RtlMoveMemory() for decryption pattern detection");
    }
} catch (e) {}

// Hook VirtualProtect (often used before decrypting code/data in memory)
try {
    const virtualProtect = Module.findExportByName("kernel32.dll", "VirtualProtect");
    if (virtualProtect) {
        Interceptor.attach(virtualProtect, {
            onEnter: function(args) {
                this.address = args[0];
                this.size = args[1].toInt32();
                this.newProtect = args[2].toInt32();
                this.oldProtect = args[3];
                
                // PAGE_EXECUTE_READWRITE = 0x40
                // PAGE_READWRITE = 0x04
                if (this.newProtect === 0x40 || this.newProtect === 0x04) {
                    console.log("\n[VIRTUAL PROTECT] Memory protection changed (possible decryption)");
                    console.log("  Address:", this.address);
                    console.log("  Size:", this.size, "bytes");
                    console.log("  New Protection:", "0x" + this.newProtect.toString(16));
                    
                    // Try to read data at this location
                    try {
                        console.log("  Data at location:", hexdump_local(this.address, Math.min(this.size, 128)));
                    } catch (e) {}
                }
            }
        });
        console.log("[+] Hooked VirtualProtect()");
    }
} catch (e) {}

// Hook RC4 if present (common in malware)
console.log("[*] Searching for RC4 implementations...");

// Hook common deobfuscation: XOR with key
// We can try to find XOR loops by hooking functions that contain them
// This is more advanced and depends on the malware

// Hook CryptUnprotectData (DPAPI)
try {
    const cryptUnprotectData = Module.findExportByName("crypt32.dll", "CryptUnprotectData");
    if (cryptUnprotectData) {
        Interceptor.attach(cryptUnprotectData, {
            onEnter: function(args) {
                // DATA_BLOB structure
                this.pDataIn = args[0];
                try {
                    const cbData = Memory.readU32(this.pDataIn);
                    const pbData = Memory.readPointer(this.pDataIn.add(Process.pointerSize === 8 ? 8 : 4));
                    
                    console.log("\n" + "=".repeat(80));
                    console.log("[DPAPI] CryptUnprotectData - ENCRYPTED");
                    console.log("  Encrypted Length:", cbData, "bytes");
                    console.log("  Encrypted Data:", hexdump_local(pbData, cbData, 256));
                } catch (e) {}
                
                this.pDataOut = args[1];
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) { // Success
                    try {
                        const cbData = Memory.readU32(this.pDataOut);
                        const pbData = Memory.readPointer(this.pDataOut.add(Process.pointerSize === 8 ? 8 : 4));
                        
                        console.log("\n[DPAPI] CryptUnprotectData - DECRYPTED!");
                        console.log("  Decrypted Length:", cbData, "bytes");
                        console.log("  Decrypted Data:", hexdump_local(pbData, cbData, 512));
                        
                        const str = tryReadAsString(pbData, cbData);
                        if (str) {
                            console.log("  [DECRYPTED STRING]:", str);
                        }
                        console.log("=".repeat(80));
                    } catch (e) {}
                }
            }
        });
        console.log("[+] Hooked CryptUnprotectData() [DPAPI]");
    }
} catch (e) {}

console.log("\n[*] All crypto hooks installed. Monitoring for decryption operations...\n");
console.log("[!] TIP: Decrypted secrets will be shown in plaintext after decryption!\n");