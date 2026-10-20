FROM python:3.12-slim
# TrueNorth pii-scan scanner image — presidio stack PREBAKED so check legs
# don't pay a cold `pip install presidio+spacy` on every ephemeral engine
# (each ARC pod = own engine = empty cache volume; that install was ~6 of
# pii-scan's 9 minutes). Worker file is mounted at run time by the module
# (with_new_file), so only the dependency stack lives here. Pinned (FR-14).
RUN pip install --no-cache-dir presidio-analyzer==2.2.35
