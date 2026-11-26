from gamai_plugins.cli import call

if __name__ == "__main__":
    print(call("trust", "managed_policy", {"action": "load"}))
    print(call("protean", "run", {"cmd": "echo hello", "risk": "low", "timeout_s": 5}))
