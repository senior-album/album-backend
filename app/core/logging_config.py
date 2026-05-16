"""
T-123: 구조화 JSON 로그 설정.

Loki 가 line-based text 를 파싱할 때 labels/fields 추출이 취약해 "긴 trace
+ 정규식" 조합을 피하기 어렵다. stdout 을 처음부터 JSON 으로 흘려 보내면
Loki/Promtail 의 `json` stage 한 줄로 level/name/trace_id 를 label 로 승격
가능. 포맷 분기(dev: text, prod: json)는 두지 않고 항상 JSON — jq 로 읽으면
되고 구현/운영이 분기 없이 단순해진다.
"""

from __future__ import annotations

import logging
from typing import Iterable

from pythonjsonlogger import jsonlogger

from app.core.logging_filters import OtelTraceContextFilter, PIIRedactionFilter


_JSON_FORMAT = (
    "%(asctime)s %(levelname)s %(name)s %(message)s "
    "%(module)s %(funcName)s %(lineno)d "
    # T-318: 두 OTel 필드를 format string 에 명시적으로 두는 게 핵심.
    # jsonlogger 2.0.7 의 `_perform_rename_log_fields` 는 `log_record[old]` 가
    # 항상 존재한다고 가정 (가드 없음). format string 에 있어야 add_fields 의
    # 첫 루프 (`for field in self._required_fields: log_record[field] = record.__dict__.get(field)`)
    # 가 key 를 채워주고 rename 단계에서 KeyError 가 안 난다. record 에 attr
    # 가 없으면 .get() → None 으로 떨어져 `"trace_id": null` 로 직렬화 — 안전.
    # 추가로 아래 OtelTraceContextFilter 가 None 대신 빈 문자열로 채워 일관성.
    "%(otelTraceID)s %(otelSpanID)s"
)


def configure_logging(level: int = logging.INFO) -> None:
    """root logger 를 JSON formatter 로 재구성.

    `logging.basicConfig` 는 root 에 핸들러가 이미 있으면 no-op 이라 idempotent
    를 보장하지 않는다. 직접 핸들러를 교체한다.
    """
    root = logging.getLogger()
    root.setLevel(level)

    # 기존 핸들러 정리
    for h in list(root.handlers):
        root.removeHandler(h)

    formatter = jsonlogger.JsonFormatter(
        _JSON_FORMAT,
        rename_fields={
            "asctime": "ts",
            "levelname": "level",
            "name": "logger",
            # T-122: opentelemetry LoggingInstrumentor 가 LogRecord 에 주입하는
            # 속성명. 미주입 (tracing 비활성) 시엔 빈 문자열 — Loki 쿼리는 그대로.
            "otelTraceID": "trace_id",
            "otelSpanID": "span_id",
        },
    )

    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    # T-318: OtelTraceContextFilter 는 Handler 에 attach 해야 한다.
    # root logger 에 addFilter 하면 propagate 된 child record (uvicorn.access
    # 같은) 에 적용되지 않아 `rename_fields` 가 KeyError 로 access log 를
    # traceback dump 로 깨뜨린다. Handler.handle 은 emit 전에 모든 propagated
    # record 에 대해 자기 filter 를 돌리므로 안전.
    stream.addFilter(OtelTraceContextFilter())
    root.addHandler(stream)

    # T-103 PII 마스킹 필터 유지
    root.addFilter(PIIRedactionFilter())

    # T-122: OTel LoggingInstrumentor (`init_tracing` 활성 시) 가 LogRecord 에
    # `otelTraceID` / `otelSpanID` 속성을 자동 주입한다 — 단 활성 span context
    # 가 있을 때만. trace 밖 (uvicorn access 등) record 는 위 OtelTraceContextFilter
    # 가 빈 문자열로 채워준다. 위 `rename_fields` 매핑이 두 키를 `trace_id` /
    # `span_id` 로 변환해 JSON 출력 (Loki ↔ Tempo 점프 키) 으로 흘려보낸다.

    # uvicorn 기본 포맷터가 txt 라 재구성 — propagation 으로 root 에 맡긴다.
    _rewire_uvicorn_loggers(["uvicorn", "uvicorn.error", "uvicorn.access"])


def _rewire_uvicorn_loggers(names: Iterable[str]) -> None:
    for name in names:
        lg = logging.getLogger(name)
        for h in list(lg.handlers):
            lg.removeHandler(h)
        lg.propagate = True
