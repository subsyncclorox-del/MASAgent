# Minimal PoC-validation sandbox.
#
# Runs one reproduction recipe and prints a JSON verdict. Kept tiny and
# dependency-free (stdlib only) so it starts fast and has minimal attack surface.
# The runtime invokes it with strict limits: --cap-drop ALL, no-new-privileges,
# constrained cpu/memory/pids, and egress only via SCOPEGUARD_PROXY.
FROM python:3.12-slim

# Non-root by default.
RUN useradd --create-home --uid 10001 masa
USER masa
WORKDIR /home/masa

COPY entrypoint.py /home/masa/entrypoint.py

# The recipe arrives on stdin; the verdict is printed on stdout as JSON.
ENTRYPOINT ["python3", "/home/masa/entrypoint.py"]
