"""
资产收集工具 — API 接口层

Blueprint 注册入口，所有 API 路由统一通过 /api 前缀挂载。

目录结构:
    api/
    ├── __init__.py       # Blueprint 注册入口 (本文件)
    ├── tools.py          # /api/tools, /api/databases       — 工具列表 & 数据库信息
    ├── scan.py           # /api/run, /api/tool/<name>/run   — 扫描执行
    ├── results.py        # /api/results, /api/tool/<name>/results, /api/export — 结果查询 & 导出
    ├── upload.py         # /api/upload                      — Agent 目标上传
    └── settings.py       # /api/settings                    — 系统配置

调用流程:
    Frontend → API 路由 → tool_runner / storage → SQLite 数据库
"""

from flask import Blueprint

api_bp = Blueprint("api", __name__, url_prefix="/api")

from api import tools     # noqa: E402, F401
from api import scan      # noqa: E402, F401
from api import results   # noqa: E402, F401
from api import upload    # noqa: E402, F401
from api import settings  # noqa: E402, F401
