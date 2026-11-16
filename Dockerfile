# Linux/Python 3.12 deployment; update this digest through reviewed dependency PRs.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 \
    TIMELINE_VIEWER_MODE=oidc STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
COPY requirements/runtime-py312-linux.txt /opt/timeline/requirements.txt
RUN python -m pip install --require-hashes -r /opt/timeline/requirements.txt
COPY dist/*.whl /opt/timeline/wheels/
RUN python -m pip install --no-deps /opt/timeline/wheels/*.whl \
    && rm -r /opt/timeline/wheels \
    && groupadd --gid 10001 timeline \
    && useradd --uid 10001 --gid 10001 --no-create-home timeline
COPY streamlit_timeline_ui/app.py /opt/timeline/viewer.py
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["timeline"]
CMD ["--help"]
