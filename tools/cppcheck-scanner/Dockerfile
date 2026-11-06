# Prebaked cppcheck scanner image for the TrueNorth lint check.
# Prebake rule: every check leg runs on a fresh ephemeral engine pod with an
# EMPTY cache — runtime `apt-get install` was measured at ~6 min/leg for the
# pii-scan; bake the scanner instead. debian:trixie-slim ships cppcheck 2.17.1.
FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        cppcheck=2.17.1-2 \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Verify the pinned version actually installed — fail the build otherwise.
RUN test "$(cppcheck --version | awk '{print $2}')" = "2.17.1"
