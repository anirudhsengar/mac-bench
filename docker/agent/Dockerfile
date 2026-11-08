FROM mcr.microsoft.com/playwright:v1.62.0-noble@sha256:baed2032d533817f3dbe6425de795788430ba345e819a1201337009ba17c9d07

COPY --from=ghcr.io/astral-sh/uv:0.6.6 /uv /usr/local/bin/uv

WORKDIR /app

# Install Python dependencies into system Python 3.12 (matching preinstalled Playwright 1.62.0 browsers)
RUN uv pip install --system --break-system-packages --no-cache \
      "anthropic>=0.49.0" \
      "httpx>=0.28.0" \
      "requests>=2.32.0" \
      "langchain-anthropic>=0.3.10" \
      "langchain-core>=0.3.45" \
      "langgraph>=0.3.18" \
      "pydantic>=2.10.0" \
      "pyyaml>=6.0.2" \
      "playwright==1.62.0" \
      "beautifulsoup4>=4.12.3"

COPY docker/agent/entrypoint.sh /usr/local/bin/agent-entrypoint.sh
RUN chmod +x /usr/local/bin/agent-entrypoint.sh \
 && mkdir -p /app/work \
 && chown -R pwuser:pwuser /app

ENV PYTHONPATH=/app/src \
    HTTP_PROXY=http://proxy:8080 \
    HTTPS_PROXY=http://proxy:8080 \
    http_proxy=http://proxy:8080 \
    https_proxy=http://proxy:8080 \
    NO_PROXY=127.0.0.1,localhost \
    no_proxy=127.0.0.1,localhost \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

USER pwuser

ENTRYPOINT ["/usr/local/bin/agent-entrypoint.sh"]
CMD ["sleep", "infinity"]
