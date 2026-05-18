from agent import AgentAction


def main():
    # 中文注释：启动时创建单个 Agent 实例，保证整个会话的历史持续累积
    agent = AgentAction(debug=True)

    print("=== Agent 对话模式 ===")
    print("输入 quit/exit 退出。")

    while True:
        try:
            user_input = input("\n>>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n会话结束。")
            break

        if not user_input:
            continue

        if user_input.lower() in {"quit", "exit"}:
            print("会话结束。")
            break

        result = agent.run(user_input)
        print("\nAgent:")
        print(result.get("message", ""))


if __name__ == "__main__":
    main()
