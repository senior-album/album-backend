"""
T-122: OpenTelemetry traces — 자동계측 + OTLP gRPC exporter.

배포: 셀프호스트 OTel Collector → Tempo (album-deploy/k8s/{otel-collector,tempo}.yaml).
환경변수 `OTEL_EXPORTER_OTLP_ENDPOINT` 가 비어있으면 SDK 초기화 자체를 건너뛴다
— 로컬 dev / CI 에서 endpoint 가 없을 때 OTLP exporter 의 connect retry 로그가
ERROR 레벨로 쏟아지는 걸 막기 위함. 미초기화 상태에서도 코드 호출은 다 정상
(`opentelemetry.trace.get_tracer().start_as_current_span(...)` 가 NoOp span 반환).

LoggingInstrumentor 는 `set_logging_format=False` 로 둔다 — JSON formatter 는
이미 `logging_config.py` 가 잡고 있고, instrumentor 는 LogRecord 에
`otelTraceID` / `otelSpanID` 속성만 자동 주입하면 충분 (formatter 가 직렬화).
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


def _endpoint_configured() -> bool:
    return bool(os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip())


def init_tracing(app: Any) -> None:
    """FastAPI 앱과 외부 호출 라이브러리에 자동계측을 단다.

    `app` 은 FastAPI 인스턴스. SQLAlchemy 엔진은 lifespan 에서
    Database.initialize() 직후 `instrument_sqlalchemy_engine` 을 따로 호출 ─
    이 시점엔 engine 이 아직 없기 때문이다.
    """
    if not _endpoint_configured():
        logger.info("OTel: OTEL_EXPORTER_OTLP_ENDPOINT 미설정 — tracing 비활성")
        return

    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    from opentelemetry.instrumentation.logging import LoggingInstrumentor
    from opentelemetry.instrumentation.redis import RedisInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    service_name = os.environ.get("OTEL_SERVICE_NAME", "album-backend")
    resource = Resource.create({"service.name": service_name})

    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)

    FastAPIInstrumentor.instrument_app(app)
    AsyncPGInstrumentor().instrument()
    HTTPXClientInstrumentor().instrument()
    RedisInstrumentor().instrument()
    LoggingInstrumentor().instrument(set_logging_format=False)

    logger.info(
        "OTel: tracing 활성 (service.name=%s, exporter=otlp/grpc)",
        service_name,
    )


def instrument_sqlalchemy_engine(engine: Any) -> None:
    """SQLAlchemy AsyncEngine 을 자동계측에 등록.

    Database.initialize() 가 engine 을 만든 직후 호출. endpoint 미설정이면
    no-op (SDK 미초기화 상태에서 instrumentor 만 돌면 기록 대상이 없어 무해
    하지만 import 비용을 아끼기 위해 가드).
    """
    if not _endpoint_configured():
        return

    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

    SQLAlchemyInstrumentor().instrument(engine=engine.sync_engine)
