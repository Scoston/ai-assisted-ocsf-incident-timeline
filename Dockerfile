# Linux/Python 3.12 deployment; update this digest through reviewed dependency PRs.
FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
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
