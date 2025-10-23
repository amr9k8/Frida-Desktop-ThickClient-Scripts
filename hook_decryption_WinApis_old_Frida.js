

var __dumpCounter = 0;
function tryWriteFile(path, content) {
  __dumpCounter++;
  try {
    var f = new File(path, "w");
    f.write(content);
    f.flush();
    f.close();
    return true;
  } catch(e) { return false; }
}
function timestamp() {
  return Math.floor(Date.now()/1000);
}
function hexdumpIfPrintable(ptr, len) {
  try {
    if (!ptr || ptr.isNull() || len <= 0) return;
    var s = Memory.readUtf8String(ptr, Math.min(len, 2048));
    if (s && s.indexOf("BEGIN RSA PRIVATE KEY") !== -1) {
      console.log("[*] ASCII contains PEM header:");
      console.log(s.substring(0, Math.min(s.length, 8192)));
    } else {
      // basic printable heuristic
      var printable = 0;
      for (var i=0;i<Math.min(s.length,1000);i++){
        var c = s.charCodeAt(i);
        if (c >= 0x20 && c <= 0x7E) printable++;
      }
      if (printable / Math.max(1, Math.min(s.length,1000)) > 0.6) {
        console.log(hexdump(ptr, { length: Math.min(len,2048), header: false }));
      }
    }
  } catch(e){}
}

// map file handles -> path for CreateFile / ReadFile
var handleToPath = {};


// Crypto API / DPAPI / CNG hooks
function hookCryptoApis() {
  // CryptUnprotectData (crypt32.dll) - DPAPI
  var p = Module.findExportByName("Crypt32.dll", "CryptUnprotectData");
  if (p) {
    Interceptor.attach(p, {
      onEnter: function(args) {
        this.pDataOut = args[6]; // DATA_BLOB *pDataOut
      },
      onLeave: function(ret) {
        try {
          if (!this.pDataOut.isNull()) {
            // DATA_BLOB: typedef struct _CRYPTOAPI_BLOB { DWORD cbData; BYTE *pbData; } DATA_BLOB;
            var cb = Memory.readU32(this.pDataOut);
            var pb = Memory.readPointer(this.pDataOut.add(Process.pointerSize));
            if (cb > 0 && !pb.isNull()) {
              if (cb > 0 && cb < 20000) {
                try {
                  var s = Memory.readUtf8String(pb, cb);
                  console.log("[CryptUnprotectData] plaintext (len=" + cb + "):");
                  console.log(s.substring(0, Math.min(s.length, 8192)));
                  var outPath = "C:\\temp\\frida_dpapi_" + timestamp() + (__dumpCounter++) + ".bin";
                  tryWriteFile(outPath, s);
                  console.log("[Saved] DPAPI output -> " + outPath);
                } catch(e){}
              }
            }
          }
        } catch(e){}
      }
    });
    console.log("[+] hooked CryptUnprotectData");
  }

  // CryptDecrypt (advapi32.dll)
  var cdec = Module.findExportByName("Advapi32.dll", "CryptDecrypt") || Module.findExportByName("Crypt32.dll","CryptDecrypt");
  if (cdec) {
    Interceptor.attach(cdec, {
      onEnter: function(args) {
        this.pbData = args[4]; // BYTE *pbData
        this.pdwDataLen = args[5]; // DWORD *pdwDataLen
      },
      onLeave: function(ret) {
        try {
          if (!this.pdwDataLen.isNull()) {
            var len = Memory.readU32(this.pdwDataLen);
            if (len > 0 && len < 20000) {
              console.log("[CryptDecrypt] output len=" + len);
              hexdumpIfPrintable(this.pbData, len);
              try {
                var s = Memory.readUtf8String(this.pbData, len);
                var outPath = "C:\\temp\\frida_cryptdec_" + timestamp() + (__dumpCounter++) + ".bin";
                tryWriteFile(outPath, s);
                console.log("[Saved] CryptDecrypt output -> " + outPath);
              } catch(e){}
            }
          }
        } catch(e){}
      }
    });
    console.log("[+] hooked CryptDecrypt");
  }

  // NCryptDecrypt (ncrypt.dll) - CNG
  var ncd = Module.findExportByName("ncrypt.dll", "NCryptDecrypt");
  if (ncd) {
    Interceptor.attach(ncd, {
      onEnter: function(args) {
        this.pbOutput = args[4]; // PBYTE pbOutput
        this.pcbResult = args[6]; // DWORD *pcbResult
      },
      onLeave: function(ret) {
        try {
          if (!this.pcbResult.isNull()) {
            var outlen = Memory.readU32(this.pcbResult);
            if (outlen > 0 && outlen < 20000) {
              console.log("[NCryptDecrypt] output len=" + outlen);
              hexdumpIfPrintable(this.pbOutput, outlen);
            }
          }
        } catch(e){}
      }
    });
    console.log("[+] hooked NCryptDecrypt");
  }

  // BCryptDecrypt (bcrypt.dll)
  var bcd = Module.findExportByName("bcrypt.dll", "BCryptDecrypt");
  if (bcd) {
    Interceptor.attach(bcd, {
      onEnter: function(args) {
        this.pbOutput = args[4]; // PUCHAR pbOutput
        this.pcbResult = args[6]; // ULONG *pcbResult
      },
      onLeave: function(ret) {
        try {
          if (!this.pcbResult.isNull()) {
            var outlen = Memory.readU32(this.pcbResult);
            if (outlen > 0 && outlen < 20000) {
              console.log("[BCryptDecrypt] output len=" + outlen);
              hexdumpIfPrintable(this.pbOutput, outlen);
            }
          }
        } catch(e){}
      }
    });
    console.log("[+] hooked BCryptDecrypt");
  }

  // CryptImportKey (advapi32) - see if importing a PEM/DER blob
  var cimp = Module.findExportByName("Advapi32.dll", "CryptImportKey");
  if (cimp) {
    Interceptor.attach(cimp, {
      onEnter: function(args) {
        try { this.pbData = args[2]; this.dwLen = args[3].toInt32 ? args[3].toInt32() : parseInt(args[3]); } catch(e){}
      },
      onLeave: function(ret) {
        try {
          if (this.pbData && this.dwLen && this.dwLen > 0 && this.dwLen < 20000) {
            console.log("[CryptImportKey] dwLen=" + this.dwLen);
            hexdumpIfPrintable(this.pbData, this.dwLen);
          }
        } catch(e){}
      }
    });
    console.log("[+] hooked CryptImportKey");
  }
}


console.log("[*] loader: installing hooks");
hookCryptoApis();
console.log("[*] all hooks installed - monitoring. Trigger the decryption actions now.");
