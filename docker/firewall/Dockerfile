FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

RUN apk add --no-cache iptables iproute2 python3

WORKDIR /app
COPY firewall_ctl.py /app/firewall_ctl.py

CMD ["python3", "/app/firewall_ctl.py", "daemon"]
