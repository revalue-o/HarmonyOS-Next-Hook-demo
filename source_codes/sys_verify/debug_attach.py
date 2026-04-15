import frida
import sys
import time
import traceback

def on_message(message, data):
    print(f"[MSG] {message}")
    if data:
        print(f"[DATA] {len(data)} bytes")

def on_detached(reason, crash):
    print(f"[DETACHED] reason={reason}")
    if crash:
        print(f"[CRASH] {crash}")

try:
    print("[*] Connecting to frida-server...")
    manager = frida.get_device_manager()
    device = manager.add_remote_device("127.0.0.1:27042")
    print(f"[+] Connected: {device.name}")

    # Get the PID of our target
    procs = device.enumerate_processes()
    target_procs = [p for p in procs if 'sys_verify' in p.name]
    print(f"[*] Target processes: {target_procs}")

    if not target_procs:
        print("[-] com.example.sys_verify not found")
        sys.exit(1)

    pid = target_procs[0].pid
    print(f"[*] Attempting to attach to PID {pid}...")

    # Try to attach with error handling
    try:
        session = device.attach(pid)
        session.on('detached', on_detached)
        print(f"[+] Successfully attached to PID {pid}")
        print(f"[*] Session info: is_detached={session.is_detached}")
    except frida.TransportError as e:
        print(f"[-] Transport error during attach: {e}")
        print(f"[-] This typically means frida-server crashed during injection")
        print(f"[-] Trying to attach to a simpler process for comparison...")

        # Try a simpler process
        simple_procs = [p for p in procs if 'hilog' in p.name.lower()]
        if simple_procs:
            simple_pid = simple_procs[0].pid
            print(f"[*] Trying to attach to hilog (PID {simple_pid})...")
            try:
                session2 = device.attach(simple_pid)
                print(f"[+] Successfully attached to hilog! The issue is specific to com.example.sys_verify")
                session2.detach()
            except Exception as e2:
                print(f"[-] Also failed on hilog: {e2}")
                print(f"[-] The issue is with frida-server injection overall")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {type(e).__name__}: {e}")
        traceback.print_exc()
        sys.exit(1)

    # If we got here, attach succeeded
    print("[*] Loading hook script...")
    with open("hook.js", "r", encoding="utf-8") as f:
        script_source = f.read()

    script = session.create_script(script_source)
    script.on('message', on_message)

    print("[*] Loading script into process...")
    script.load()
    print("[+] Script loaded successfully!")
    print("[*] Script running. Waiting 60s for events...")

    time.sleep(60)
    print("[*] Detaching...")
    session.detach()
    print("[+] Done")

except frida.TransportError as e:
    print(f"[-] Connection error: {e}")
except Exception as e:
    print(f"[-] Error: {type(e).__name__}: {e}")
    traceback.print_exc()
