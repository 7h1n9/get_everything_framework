"""
POST /api/upload — Agent 页面上传目标文件

流程:
    任意格式(.txt/.csv/.xlsx/.json) → 解析归一化 → 输出纯 .txt
    → 返回 file_path → Agent 可直传 POST /api/run 批量扫描
"""

import os
import time

from flask import jsonify, request, session
from werkzeug.utils import secure_filename

from api import api_bp
from config import UPLOAD_DIR
from target_parser import parse_targets_file, save_normalized_targets

ALLOWED_EXTENSIONS = {".txt", ".csv", ".xlsx", ".json"}


@api_bp.route("/upload", methods=["POST"])
def upload_file():
    """
    上传目标文件

    Content-Type: multipart/form-data
        file: .txt / .csv / .xlsx / .json

    Response:
        {
            ok: true,
            file_path: "uploads/xxx_normalized.txt",    ← 可直接传给 /api/run
            target_count: N,
            targets_preview: [...]
        }

    下一步调用:
        POST /api/run  {"file_path": "<返回的 file_path>", "tools": ["subfinder"]}
    """
    file = request.files.get("file")
    if not file:
        return jsonify({"ok": False, "error": "未上传文件"}), 400

    filename = secure_filename(file.filename or "")
    if not filename or os.path.splitext(filename)[1].lower() not in ALLOWED_EXTENSIONS:
        return jsonify({"ok": False, "error": "仅支持 .txt / .csv / .xlsx / .json 文件"}), 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    ts = int(time.time())
    raw_path = os.path.join(UPLOAD_DIR, f"{ts}_{filename}")
    normalized_path = os.path.join(UPLOAD_DIR, f"{ts}_normalized.txt")
    file.save(raw_path)

    # 解析 → 去重 → 归一化 → 输出纯 .txt
    targets = parse_targets_file(raw_path)
    if not targets:
        return jsonify({"ok": False, "error": "文件中未识别到有效目标"}), 400

    save_normalized_targets(targets, normalized_path)

    session["uploaded_targets"] = {
        "file_path": normalized_path,
        "target_count": len(targets),
        "targets_preview": targets[:20],
        "label": filename,
    }

    return jsonify({
        "ok": True,
        "file_path": normalized_path,
        "target_count": len(targets),
        "targets_preview": targets[:20],
    })
