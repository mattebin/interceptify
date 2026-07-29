"""Frida reconnaissance on Spotify: list processes, try to attach, enumerate
modules + look for a TLS library / SSL_read/SSL_write exports. Tells us whether
we can instrument Spotify from here and where the crypto lives."""
import sys

try:
    import frida
except ImportError:
    # An undeclared dependency that is not in requirements.txt, because this is
    # a research tool rather than part of the product. Saying so beats a raw
    # ImportError traceback that looks like the script is broken.
    sys.exit("frida is not installed. This is a diagnostic tool, not part of "
             "Interceptify itself:\n    pip install -r requirements-dev.txt")

JS = r"""
const mods = Process.enumerateModules();
const interesting = mods.filter(m => /ssl|crypto|tls|quic|boringssl|cef|chrome|nss|schannel|winhttp|cronet/i.test(m.name));
const exps = [];
['SSL_write','SSL_read','SSL_new','SSL_CTX_new','SSL_CTX_set_keylog_callback','BIO_write'].forEach(n => {
  try { const a = Module.findExportByName(null, n); if (a) exps.push(n + ' @ ' + a); } catch(e){}
});
send({ moduleCount: mods.length, interesting: interesting.map(m => m.name + '  (' + m.size + 'b)  ' + m.path), sslExports: exps });
"""

dev = frida.get_local_device()
procs = [p for p in dev.enumerate_processes() if "spotify" in p.name.lower()]
print("Spotify processes:", [(p.pid, p.name) for p in procs] or "NONE RUNNING")
if not procs:
    sys.exit("No Spotify process — launch Spotify first.")

for p in procs:
    print("\n=== attach pid=%d %s ===" % (p.pid, p.name))
    try:
        session = dev.attach(p.pid)
    except Exception as e:
        print("  ATTACH FAILED:", type(e).__name__, e)
        print("  (if 'access is denied'/'permission', Spotify is elevated — Frida must run elevated too)")
        continue
    try:
        out = {}
        script = session.create_script(JS)
        script.on("message", lambda m, d: out.update(m.get("payload", {})) if m.get("type") == "send" else print("  msg:", m))
        script.load()
        print("  modules:", out.get("moduleCount"))
        print("  SSL exports:", out.get("sslExports") or "(none — TLS is statically linked / no exports)")
        print("  crypto/net modules:")
        for m in (out.get("interesting") or []):
            print("    ", m)
        script.unload()
    except Exception as e:
        print("  script error:", type(e).__name__, e)
    finally:
        try: session.detach()
        except Exception: pass
