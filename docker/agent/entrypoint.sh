#!/usr/bin/env bash
set -euo pipefail

# Start lightweight loopback-to-Unix-socket forwarder (127.0.0.1:18080 -> /run/llm-relay/anthropic.sock)
python3 - <<'PY' &
import asyncio
import os

SOCK_PATH = os.environ.get("LLM_RELAY_SOCK", "/run/llm-relay/anthropic.sock")

async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def handle_client(c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter) -> None:
    try:
        u_reader, u_writer = await asyncio.open_unix_connection(SOCK_PATH)
    except Exception:
        c_writer.close()
        return
    await asyncio.gather(pipe(c_reader, u_writer), pipe(u_reader, c_writer))

async def main() -> None:
    server = await asyncio.start_server(handle_client, "127.0.0.1", 18080)
    async with server:
        await server.serve_forever()

asyncio.run(main())
PY

exec "$@"
