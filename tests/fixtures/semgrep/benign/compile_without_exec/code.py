def load_config(source: str):
    return compile(source, "<config>", "exec")
