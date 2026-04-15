"""Run hook_recon.js via Frida Python binding"""
import frida
import sys
import time

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[SEND] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[ERROR] {message['description']}")
        print(f"  Stack: {message.get('stack', 'N/A')}")
    else:
        print(f"[MSG] {message}")

def main():
    print("[*] Connecting to frida-server...")
    try:
        manager = frida.get_device_manager()
        device = manager.add_remote_device("127.0.0.1:27042")
        print(f"[+] Connected to device: {device.name}")
    except Exception as e:
        print(f"[-] Failed to connect: {e}")
        sys.exit(1)

    print("[*] Attaching to com.example.sys_verify...")
    spawned_pid = None
    try:
        # Try spawn mode first (more reliable on HarmonyOS)
        print("[*] Trying spawn mode...")
        spawned_pid = device.spawn(["com.example.sys_verify"])
        print(f"[+] Spawned pid={spawned_pid}")
        session = device.attach(spawned_pid)
        print(f"[+] Attached to spawned process")
    except Exception as e1:
        print(f"[!] Spawn mode failed: {e1}")
        print("[*] Trying attach mode...")
        try:
            session = device.attach("com.example.sys_verify")
            print(f"[+] Attached to running process")
        except Exception as e2:
            print(f"[-] Failed to attach: {e2}")
            sys.exit(1)

    session.on('detached', lambda reason, crash: print(f"[!] Detached: {reason}"))

    print("[*] Loading hook_recon.js...")
    with open(r"C:\Master\Harmony\openHarmony\sys_verify\hook_recon.js", "r", encoding="utf-8") as f:
        script_source = f.read()

    script = session.create_script(script_source)
    script.on('message', on_message)

    print("[*] Starting script...")
    script.load()

    # Resume if we spawned the process
    if spawned_pid is not None:
        print("[*] Resuming spawned process...")
        device.resume(spawned_pid)

    print("[+] Script loaded. Press Ctrl+C to detach.")
    print("[+] NOW click 'Get Location (ArkTS)' in the app!\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Detaching...")
        session.detach()
        print("[+] Done.")

if __name__ == "__main__":
    main()
