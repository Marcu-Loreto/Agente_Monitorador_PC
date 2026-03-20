try:
    from langchain.agents import AgentExecutor, create_openai_functions_agent
    print("OK: langchain.agents")
except ImportError as e:
    print(f"FAIL langchain.agents: {e}")
    try:
        from langchain_classic.agents import AgentExecutor, create_openai_functions_agent
        print("OK: langchain_classic.agents")
    except ImportError as e2:
        print(f"FAIL langchain_classic.agents: {e2}")
