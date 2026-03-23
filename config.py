import os

# Subfinder 相关配置
SUBFINDER_CONFIG = {
    "path": "subfinder",  # 如果在环境变量中，直接写名字；否则写绝对路径
    "threads": 50,        # 并发线程数
    "timeout": 10,        # 超时时间
    "silent": True,       # 是否开启静默模式
}

# 输出配置
OUTPUT_DIR = "results"
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# API 密钥或其他敏感信息（如果有的话）
# 建议从环境变量读取：os.getenv("SUBFINDER_API_KEY")