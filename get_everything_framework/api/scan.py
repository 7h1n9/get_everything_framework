"""
模块: api/scan.py
功能: 提供扫描执行的 API 接口

路由:
  POST /api/run                   — 对指定域名/文件批量执行扫描工具
  POST /api/tool/<tool_name>/run  — 对指定域名运行单个扫描工具

调用链: API → tool_runner.load_tools() / run_tools() / run_single_tool() → SQLite 存储
"""

from flask import jsonify, request

from api import api_bp            # Flask 蓝图实例
from storage import ScanResultStore  # 扫描结果持久化存储
# 工具加载与执行的核心函数
from tool_runner import load_tools, run_single_tool, run_tools


def _normalize_domain(value: str | None) -> str | None:
    """
    规范化输入域名

    处理步骤:
        1. 若值为 None，直接返回 None
        2. 去除首尾空白字符
        3. 转为小写（域名大小写不敏感）
        4. 若处理结果为空字符串，返回 None

    参数:
        value: 待规范化的域名字符串，可为 None

    返回:
        str | None: 规范化后的域名字符串，或 None（输入无效时）
    """
    if value is None:
        return None
    # 去空白 + 转小写
    normalized = value.strip().lower()
    # 空字符串视为无效输入
    return normalized or None


@api_bp.route("/run", methods=["POST"])
def execute_scan():
    """
    批量扫描入口 — 对一个或多个目标执行选定的工具

    请求方式: POST
    路径: /api/run
    Content-Type: application/json

    请求体 (JSON):
        {
            "domain": "example.com",       // 目标域名（与 file_path 二选一必填）
            "tools": ["subfinder", "httpx"], // 工具名列表（支持 "tool" 单值兼容）
            "file_path": "/path/to/file"    // 可选：目标文件路径（与 domain 二选一）
        }

    响应:
        扫描报告 JSON，包含以下字段:
        - targets: 扫描目标列表
        - tools: 实际使用的工具列表
        - total_found: 发现的结果总数
        - total_inserted: 成功写入数据库的记录数
        - runs: 每个工具的详细执行结果

    错误响应:
        - 400: domain 或 file_path 未提供
        - 400: tools 参数无效（包含不支持的工具名）

    内部逻辑:
        1. 解析请求体，提取 domain/tools/file_path 参数
        2. 规范化域名（去空白、转小写）
        3. 转换单工具字符串为列表格式
        4. 校验必须提供 domain 或 file_path
        5. 加载并验证工具列表
        6. 执行批量扫描，返回报告
    """
    # 安全解析 JSON 请求体，解析失败时返回空字典
    payload = request.get_json(silent=True) or {}
    # 提取并规范化域名
    domain = _normalize_domain(payload.get("domain"))
    # 兼容 "tools" 和 "tool" 两种参数名
    tools = payload.get("tools") or payload.get("tool")
    # 提取可选的本地文件路径
    file_path = payload.get("file_path")

    # 将单个工具名字符串转换为列表，统一后续处理逻辑
    if isinstance(tools, str):
        tools = [tools]

    # 校验：domain 和 file_path 至少提供一个
    if not domain and not file_path:
        return jsonify({"error": "domain or file_path is required"}), 400

    # 加载并验证工具列表，无效工具名会抛出 ValueError
    try:
        selected_tools = load_tools(tools)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    # 执行批量扫描并写入存储
    store = ScanResultStore()
    report = run_tools(domain=domain, file_path=file_path, tools=selected_tools, store=store)
    return jsonify(report)


@api_bp.route("/tool/<tool_name>/run", methods=["POST"])
def execute_single_tool(tool_name: str):
    """
    运行单个工具 — 对指定域名执行某一个扫描工具

    请求方式: POST
    路径: /api/tool/<tool_name>/run
    路径参数:
        tool_name: 工具名称（如 subfinder, httpx, nuclei 等）

    请求体 (JSON):
        { "domain": "example.com" }    // 必填：目标域名

    响应示例:
        {
            "domain": "example.com",
            "tool_name": "subfinder",
            "category": "subdomain",
            "found_count": 42,
            "inserted_count": 42,
            "run_id": "uuid-string",
            "results": ["sub1.example.com", "sub2.example.com", ...]
        }

    错误响应:
        - 400: domain 参数缺失或为空
        - 400: tool_name 无效（不在支持的工具列表中）

    内部逻辑:
        1. 解析请求体，提取并规范化域名
        2. 校验域名是否存在
        3. 验证工具名是否合法
        4. 调用单工具扫描函数，返回结果
    """
    # 安全解析 JSON 请求体
    payload = request.get_json(silent=True) or {}
    # 提取并规范化目标域名
    domain = _normalize_domain(payload.get("domain"))

    # 校验域名必填
    if not domain:
        return jsonify({"error": "domain is required"}), 400

    # 验证工具名是否受支持
    try:
        load_tools([tool_name])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    # 创建存储实例并执行单工具扫描
    return jsonify(run_single_tool(tool_name, domain, store=ScanResultStore()))
