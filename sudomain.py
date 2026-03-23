import subprocess
import os
from config import SUBFINDER_CONFIG, OUTPUT_DIR

class SubfinderRunner:
    def __init__(self):
        self.config = SUBFINDER_CONFIG
        self.output_dir = OUTPUT_DIR

    def run_scan(self, domain):
        """执行扫描并返回结果列表"""
        output_file = os.path.join(self.output_dir, f"{domain}.txt")
        
        # 构建命令
        cmd = [
            self.config["path"],
            "-d", domain,
            "-t", str(self.config["threads"]),
            "-o", output_file,
            "-silent"
        ]

        try:
            print(f"[*] 正在扫描域名: {domain} ...")
            # 执行命令
            subprocess.run(cmd, check=True, capture_output=True)
            
            # 读取结果
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    results = [line.strip() for line in f if line.strip()]
                return results
            return []
            
        except subprocess.CalledProcessError as e:
            print(f"[!] {domain} 扫描失败: {e}")
            return []