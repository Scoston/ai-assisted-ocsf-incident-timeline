# Linux/Python 3.12 deployment; update this digest through reviewed dependency PRs.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
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
