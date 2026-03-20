missing = []
for mod in ["psutil", "dotenv", "langchain", "langchain_openai", "openai", "streamlit"]:
    try:
        __import__(mod)
        print(f"  OK  {mod}")
    except ImportError:
        print(f"  MISS {mod}")
        missing.append(mod)
print("\nMissing:", missing if missing else "None")
