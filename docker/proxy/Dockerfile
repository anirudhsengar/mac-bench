FROM python:3.12-slim-bookworm@sha256:da54eb86849fe19be7584d8b3f291fcf0c53c196760ab3d70dc6382f681ef9c0

RUN pip install --no-cache-dir "mitmproxy>=11.0.0,<12.0.0"

WORKDIR /app
COPY mediator_addon.py /app/mediator_addon.py

CMD ["mitmdump", "--listen-host", "0.0.0.0", "--listen-port", "8080", "-s", "/app/mediator_addon.py", "--set", "block_global=false", "--set", "connection_strategy=lazy"]
