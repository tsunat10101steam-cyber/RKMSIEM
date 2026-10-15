# ⚠ 이 PC 에는 Docker 가 없어 빌드/실행 검증을 하지 못했습니다. 운영 전 반드시 직접 검증하세요.
FROM python:3.12-slim
WORKDIR /app
RUN useradd -r -u 10001 rkmsiem
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY rkmsiem/ rkmsiem/
COPY config/ config/
COPY web/ web/
COPY staffdir/ staffdir/
COPY samples/ samples/
RUN mkdir -p data && chown -R rkmsiem /app/data
USER rkmsiem
ENV RKMSIEM_API__HOST=0.0.0.0
EXPOSE 8088 5514/udp
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8088/readyz',timeout=3)"
CMD ["python", "-m", "rkmsiem", "serve"]
# 담당자 관리 앱은 같은 이미지로 별도 컨테이너: command ["python", "-m", "staffdir", "serve"], STAFF_HOST=0.0.0.0, 포트 8090
