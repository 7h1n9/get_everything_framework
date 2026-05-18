from typing import Any, Dict, List, Optional

from storage import ScanResultStore

from .action import AgentAction


# 中文注释：Web 层兼容入口，支持外部传入历史并返回更新后的历史
def handle_agent_message(
    message: str,
    store: Optional[ScanResultStore] = None,
    history: Optional[List[Dict[str, str]]] = None,
    debug: bool = False,
) -> Dict[str, Any]:
    agent = AgentAction(
        store=store,
        conversation_history=history,
        debug=debug,
    )
    return agent.run(message)
