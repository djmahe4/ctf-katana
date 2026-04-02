# Frida instrumentation templates for CTF-Katana
# These can be injected or used as-is for bypass/analysis.

TEMPLATES = {
    "ssl_pinning_bypass": """
    /* Frida Script: Universal SSL Pinning Bypass 
       Bypasses checks in TrustManager, OkHttp, and WebView.
    */
    Java.perform(function() {
        console.log("[*] Injected: SSL Pinning Bypass");
        
        var TrustManager = Java.use("javax.net.ssl.TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        // Hook all possible TrustManager implementations
        var SimpleTrustManager = Java.registerClass({
             name: "com.katana.SimpleTrustManager",
             implements: [Java.use("javax.net.ssl.X509TrustManager")],
             methods: {
                 checkClientTrusted: function(chain, authType) {},
                 checkServerTrusted: function(chain, authType) {},
                 getAcceptedIssuers: function() { return []; }
             }
        });

        var TrustManagers = [SimpleTrustManager.$new()];
        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(km, tm, sr) {
            console.log("[*] SSLContext.init hooked! Forcing bypass.");
            this.init(km, TrustManagers, sr);
        };
    });
    """,

    "root_detection_bypass": """
    /* Frida Script: Simple Root Detection Bypass 
       Hooks common file checks and package names.
    */
    Java.perform(function() {
        console.log("[*] Injected: Root Detection Bypass");

        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var name = this.getName();
            if (name == "su" || name == "magisk" || name == "Superuser") {
                console.log("[*] Bypassing root file check: " + name);
                return false;
            }
            return this.exists();
        };
    });
    """,

    "native_trace": """
    /* Frida Script: Simple Native Function Tracer 
       Traces any JNI or libc calls if provided.
    */
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function(args) {
            this.path = Memory.readUtf8String(args[0]);
            console.log("[*] dlopen: " + this.path);
        }
    });

    Interceptor.attach(Module.findExportByName("libc.so", "strcmp"), {
        onEnter: function(args) {
            var str1 = Memory.readUtf8String(args[0]);
            var str2 = Memory.readUtf8String(args[1]);
            if (str1.indexOf("CTF") !== -1 || str2.indexOf("CTF") !== -1) {
                console.log("[*] strcmp comparison: " + str1 + " <=> " + str2);
            }
        }
    });
    """
}
