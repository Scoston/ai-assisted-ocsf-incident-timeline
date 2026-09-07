# Immutable dependency image plus the complete reviewed upstream source revision.
FROM log2timeline/plaso@sha256:a8d42e64dcd3af2dffed8ddb25d34f34def69b672eec97ea9af62885c9332950
USER root
ADD --checksum=sha256:6fb3d63469b0b112b56ad08249bd344b48b4268b75b51fd122a35037f9f0e0c5 https://codeload.github.com/log2timeline/plaso/tar.gz/00fcc6e7f95a002c85464f0dfd193396bd7d86d3 /tmp/plaso-source.tar.gz
RUN mkdir /opt/plaso-source && tar -xzf /tmp/plaso-source.tar.gz --strip-components=1 -C /opt/plaso-source && rm /tmp/plaso-source.tar.gz
ENV PYTHONPATH=/opt/plaso-source
ENV PYTHONDONTWRITEBYTECODE=1
ENV HOME=/tmp
COPY probe.py check_upstream.py /opt/timeline-plaso/
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["python3", "/opt/timeline-plaso/probe.py"]
CMD ["inventory"]
