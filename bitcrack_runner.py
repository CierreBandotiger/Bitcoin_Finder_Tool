import subprocess
import os
import sys
import time
import psutil
import threading

class BitCrackRunner:
    def __init__(self, bitcrack_path):
        self.bitcrack_path = bitcrack_path
        if not os.path.exists(self.bitcrack_path):
            sys.exit(1)
        self.process = None

    def start_search(self, start_hex, end_hex, target_address, device_id=0):
        if self.process is not None and self.process.poll() is None:
            return False
        keyspace = f"{start_hex}:{end_hex}"
        cmd = [
            self.bitcrack_path,
            "--keyspace", keyspace,
            "--target", target_address,
            "--device", str(device_id),
            "-o", "found.txt",
            "--stride", "1"
        ]
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
        self.output_thread = threading.Thread(target=self._read_output, daemon=True)
        self.output_thread.start()
        return True

    def _read_output(self):
        for line in iter(self.process.stdout.readline, ''):
            if not line and self.process.poll() is not None:
                break
            if line.strip():
                print(line.strip())
        self.process.stdout.close()
        self.process.wait()

    def stop_search(self):
        if self.process is not None:
            try:
                parent = psutil.Process(self.process.pid)
                for child in parent.children(recursive=True):
                    child.terminate()
                parent.terminate()
            except psutil.NoSuchProcess:
                pass
            self.process = None

    def is_running(self):
        return self.process is not None and self.process.poll() is None