'use strict';

function findExport(moduleName, exportName) {
    try {
        const mod = Process.findModuleByName(moduleName);
        return mod ? mod.findExportByName(exportName) : null;
    } catch (e) { return null; }
}

Interceptor.attach(findExport("crypt32.dll", "CertVerifyCertificateChainPolicy"), {
    onEnter: function(args) { this.pPolicyStatus = args[3]; },
    onLeave: function(retval) {
        try {
            if (this.pPolicyStatus && !this.pPolicyStatus.isNull()) {
                this.pPolicyStatus.add(4).writeU32(0);
                this.pPolicyStatus.add(8).writeU32(0xFFFFFFFF);
                this.pPolicyStatus.add(12).writeU32(0xFFFFFFFF);
            }
            retval.replace(ptr(1));
        } catch (e) {}
    }
});