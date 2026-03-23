import argparse
import sys
from sudomain import SubfinderRunner

def main():
    # 1. 设置命令行参数解析
    parser = argparse.ArgumentParser(description="自动化子域名收集工具")
    parser.add_argument("-d", "--domain", help="要扫描的目标域名")
    parser.add_argument("-f", "--file", help="包含域名列表的文本文件")
    
    args = parser.parse_args()

    # 2. 检查输入
    if not args.domain and not args.file:
        parser.print_help()
        sys.exit(1)

    # 3. 初始化扫描器
    scanner = SubfinderRunner()
    targets = []

    if args.domain:
        targets.append(args.domain)
    
    if args.file:
        with open(args.file, "r") as f:
            targets.extend([line.strip() for line in f if line.strip()])

    # 4. 循环执行任务
    print(f"--- 任务开始，共 {len(targets)} 个目标 ---")
    
    total_found = 0
    for target in targets:
        results = scanner.run_scan(target)
        print(f"[+] {target} 扫描完成，发现 {len(results)} 个子域名")
        total_found += len(results)

    print(f"--- 所有任务已完成，累计发现 {total_found} 个子域名 ---")

if __name__ == "__main__":
    main()