import os

OUTPUT_DIR = "results"
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

SQLITE_CONFIG = {
    "path": os.path.join(OUTPUT_DIR, "scan_results.db"),
}

# 目标配置
# domains: 直接写要收集的目标域名列表
# domain_file: 从文件中读取目标域名，一行一个
TARGET_CONFIG = {
    "domains": [
        "nfl.com",
    ],
    "domain_file": None,
}

# 主流程配置
SCAN_CONFIG = {
    "enabled_runners": ["amass"],  # 可选: amass / subfinder / dnsx
}

# Amass Enum 相关配置
AMASS_CONFIG = {
    "path": "amass",          # 如果在环境变量中，直接写名字；否则写绝对路径
    "timeout": 30,            # 超时时间(分钟)，对应 amass -timeout
    "passive": True,          # True 时使用被动模式
    "brute": False,           # True 时启用爆破模式
    "silent": True,           # 是否尽量减少输出
    "extra_args": [],         # 额外参数，例如 ["-active"]
}

# Subfinder 相关配置
SUBFINDER_CONFIG = {
    "path": "subfinder",      # 如果在环境变量中，直接写名字；否则写绝对路径
    "threads": 50,            # 并发线程数
    "timeout": 10,            # 超时时间(秒)
    "silent": True,           # 是否开启静默模式
}

# Dnsx 存活探测配置
DNSX_CONFIG = {
    "path": "dnsx",           # 如果在环境变量中，直接写名字；否则写绝对路径
    "threads": 50,            # 并发线程数
    "silent": True,           # 是否开启静默模式
    "resp_only": True,        # 仅输出成功解析的域名
    "extra_args": [],         # 额外参数
}
