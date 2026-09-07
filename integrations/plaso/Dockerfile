# Immutable dependency image plus the complete reviewed upstream source revision.
FROM log2timeline/plaso@sha256:a8d42e64dcd3af2dffed8ddb25d34f34def69b672eec97ea9af62885c9332950
USER root
ADD --checksum=sha256:6fb3d63469b0b112b56ad08249bd344b48b4268b75b51fd122a35037f9f0e0c5 https://codeload.github.com/log2timeline/plaso/tar.gz/00fcc6e7f95a002c85464f0dfd193396bd7d86d3 /tmp/plaso-source.tar.gz
RUN mkdir /opt/plaso-source && tar -xzf /tmp/plaso-source.tar.gz --strip-components=1 -C /opt/plaso-source && rm /tmp/plaso-source.tar.gz
ADD --checksum=sha256:8c22117b3361bb0fdf0f5931752eba33ad6c1d225fe3e1aabebe804faab3ec78 https://files.pythonhosted.org/packages/2f/d4/28d29d6ecdd18a69cbf0b4bfb370972bdd215d49b703046291edb4371d04/dfvfs-20260731-py3-none-any.whl /tmp/dfvfs.whl
ADD --checksum=sha256:a6c5f4303714d78c70da15020fb705617d0b79c5f8e5942bc943090d861ec2bd https://files.pythonhosted.org/packages/dc/0a/8f7b160eead1af3d8df396fec805fba7482be334f6b7b6e64cb1f06eb43b/dfdatetime-20260730-py3-none-any.whl /tmp/dfdatetime.whl
RUN python3 -m zipfile -e /tmp/dfvfs.whl /opt/timeline-dependencies && python3 -m zipfile -e /tmp/dfdatetime.whl /opt/timeline-dependencies && rm /tmp/dfvfs.whl /tmp/dfdatetime.whl
ENV PYTHONPATH=/opt/plaso-source:/opt/timeline-dependencies
ENV PYTHONDONTWRITEBYTECODE=1
ENV HOME=/tmp
COPY probe.py check_upstream.py /opt/timeline-plaso/
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["python3", "/opt/timeline-plaso/probe.py"]
CMD ["inventory"]
