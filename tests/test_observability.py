"""
T-122: OpenTelemetry traces 초기화 가드 단위 테스트.

핵심 안전성: `OTEL_EXPORTER_OTLP_ENDPOINT` env 가 비어 있으면 SDK 초기화를
건너뛰어야 한다. 미설정 상태에서 SDK 가 초기화되면 OTLP exporter 의
`localhost:4317` 기본값으로 connect retry 가 돌고 ERROR 로그가 쏟아져 dev/CI
경험을 망친다. 이 가드가 PR 1 (backend) 와 PR 2 (deploy) 를 안전하게 분리하는
근거이기도 하다 — backend 만 ship 돼도 endpoint env 가 없으니 no-op.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from app.core import observability


@pytest.fixture(autouse=True)
def _clear_otel_env(monkeypatch):
    """각 테스트 시작 시 OTEL_* env 를 모두 제거 — 다른 테스트 영향 차단."""
    for key in list(os.environ.keys()):
        if key.startswith("OTEL_"):
            monkeypatch.delenv(key, raising=False)
    yield


def test_endpoint_configured_false_when_unset():
    assert observability._endpoint_configured() is False


def test_endpoint_configured_false_when_blank(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "   ")
    assert observability._endpoint_configured() is False


def test_endpoint_configured_true_when_set(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")
    assert observability._endpoint_configured() is True


def test_init_tracing_noop_when_unset_does_not_import_sdk():
    """endpoint 미설정 시 init_tracing 은 SDK import 없이 조용히 끝난다.

    FastAPI 모형 객체를 넘겨도 instrument_app 호출이 일어나지 않으면
    AttributeError / TypeError 가 안 난다 — 호출이 없었다는 증거.
    """
    fake_app = object()  # FastAPI 인터페이스를 흉내내지 않는 plain object
    observability.init_tracing(fake_app)  # raises 면 fail


def test_instrument_sqlalchemy_engine_noop_when_unset():
    """engine 으로 None 을 넘겨도 미설정 가드에 걸려 AttributeError 안 남."""
    observability.instrument_sqlalchemy_engine(None)  # raises 면 fail


def test_init_tracing_active_path_wires_instrumentors(monkeypatch):
    """endpoint 가 설정되면 instrumentor 들이 호출되는지 확인.

    SDK / instrumentation 모듈 자체는 prod 에서 정상 동작하는 게 본 테스트의
    목적이 아니므로 mock 으로 대체. 가드 통과 후 호출 흐름만 검증.
    """
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")

    # FastAPIInstrumentor / 기타 4개 instrumentor 를 mock 으로 swap.
    fastapi_mock = MagicMock()
    asyncpg_mock = MagicMock()
    httpx_mock = MagicMock()
    redis_mock = MagicMock()
    logging_mock = MagicMock()
    provider_set = MagicMock()

    with patch.dict(
        "sys.modules",
        {
            "opentelemetry": MagicMock(trace=MagicMock(set_tracer_provider=provider_set)),
            "opentelemetry.exporter.otlp.proto.grpc.trace_exporter": MagicMock(
                OTLPSpanExporter=MagicMock(),
            ),
            "opentelemetry.instrumentation.asyncpg": MagicMock(
                AsyncPGInstrumentor=lambda: asyncpg_mock,
            ),
            "opentelemetry.instrumentation.fastapi": MagicMock(
                FastAPIInstrumentor=fastapi_mock,
            ),
            "opentelemetry.instrumentation.httpx": MagicMock(
                HTTPXClientInstrumentor=lambda: httpx_mock,
            ),
            "opentelemetry.instrumentation.logging": MagicMock(
                LoggingInstrumentor=lambda: logging_mock,
            ),
            "opentelemetry.instrumentation.redis": MagicMock(
                RedisInstrumentor=lambda: redis_mock,
            ),
            "opentelemetry.sdk.resources": MagicMock(Resource=MagicMock()),
            "opentelemetry.sdk.trace": MagicMock(TracerProvider=MagicMock()),
            "opentelemetry.sdk.trace.export": MagicMock(BatchSpanProcessor=MagicMock()),
        },
    ):
        fake_app = object()
        observability.init_tracing(fake_app)

    fastapi_mock.instrument_app.assert_called_once_with(fake_app)
    asyncpg_mock.instrument.assert_called_once()
    httpx_mock.instrument.assert_called_once()
    redis_mock.instrument.assert_called_once()
    logging_mock.instrument.assert_called_once()
    provider_set.assert_called_once()


def test_instrument_sqlalchemy_engine_active_path(monkeypatch):
    """endpoint 설정 시 SQLAlchemyInstrumentor 가 sync_engine 으로 호출."""
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")

    instr_mock = MagicMock()
    fake_engine = MagicMock()
    fake_engine.sync_engine = "sync-engine-sentinel"

    with patch.dict(
        "sys.modules",
        {
            "opentelemetry.instrumentation.sqlalchemy": MagicMock(
                SQLAlchemyInstrumentor=lambda: instr_mock,
            ),
        },
    ):
        observability.instrument_sqlalchemy_engine(fake_engine)

    instr_mock.instrument.assert_called_once_with(engine="sync-engine-sentinel")
