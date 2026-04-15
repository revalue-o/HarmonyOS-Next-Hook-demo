import frida
import sys
import time

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[SEND] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[ERROR] {message['stack']}")
    else:
        print(f"[MSG] {message}")

def main():
    # 读取 hook 脚本
    with open(r'C:\Master\Harmony\openHarmony\sys_verify\hook.js', 'r', encoding='utf-8') as f:
        script_code = f.read()

    # 连接设备
    print("[*] Connecting to 127.0.0.1:27042 ...")
    manager = frida.get_device_manager()
    device = manager.add_remote_device("127.0.0.1:27042")
    print(f"[+] Device: {device.name}")

    # Attach 到进程
    print("[*] Attaching to com.example.sys_verify ...")
    try:
        session = device.attach("com.example.sys_verify")
    except frida.ProcessNotFoundError:
        print("[-] Process not found. Trying spawn mode...")
        pid = device.spawn(["com.example.sys_verify"])
        session = device.attach(pid)
        print(f"[+] Spawned and attached, pid={pid}")

    print(f"[+] Attached successfully")

    # 创建并加载脚本
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[+] Script loaded. Running for 60 seconds...")
    print("[*] Trigger location request in the app now!")
    print("=" * 60)

    # 保持运行
    try:
        time.sleep(60)
    except KeyboardInterrupt:
        print("\n[*] Detaching...")
    finally:
        session.detach()
        print("[*] Done.")

if __name__ == '__main__':
    main()
