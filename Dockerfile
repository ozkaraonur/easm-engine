# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY easm ./easm
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
COPY --from=build /install /usr/local
RUN useradd --create-home easm
USER easm
WORKDIR /reports
ENTRYPOINT ["easm"]
CMD ["--help"]
