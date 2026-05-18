import sys

from mcpshield.proxy.server import main as http_main
from mcpshield.proxy.stdio_bridge import run as stdio_run


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "stdio":
        stdio_run()
    else:
        http_main()


if __name__ == "__main__":
    main()
