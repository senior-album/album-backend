"""
T-100 / T-124 PR3: storage 의 object key prefix·확장자 sanitize 검증.

`_sanitize_object_prefix` 가 path traversal (`..`, 절대 경로, null 바이트,
백슬래시) 을 모두 거부하고, 정상 prefix (시설 UUID, `{fac}/thumbnails`) 는
통과시키는지 본다. 이게 깨지면 시설 격리가 무너진다.

`StorageService.upload_file` 도 sanitize 를 통과시키는지 통합으로 한 번 더 — boto3 client 는 mock.
"""

import uuid

import pytest

from app.core import storage as storage_module
from app.core.storage import (
    StorageService,
    _sanitize_extension,
    _sanitize_object_prefix,
)


# ---------------------------------------------------------------------------
# _sanitize_object_prefix — 정상 입력
# ---------------------------------------------------------------------------


def test_sanitize_prefix_accepts_uuid_like_facility_id():
    fid = uuid.uuid4().hex
    assert _sanitize_object_prefix(fid) == fid


def test_sanitize_prefix_accepts_alphanumeric_with_underscore_and_dash():
    assert _sanitize_object_prefix("fac_abc-123") == "fac_abc-123"


def test_sanitize_prefix_accepts_two_segment_subpath():
    assert _sanitize_object_prefix("fac_abc/thumbnails") == "fac_abc/thumbnails"


def test_sanitize_prefix_strips_trailing_and_duplicate_slashes():
    """선후행/중복 슬래시는 제거되지만 segment 자체는 보존."""
    assert _sanitize_object_prefix("/fac_abc//thumbnails/") == "fac_abc/thumbnails"


# ---------------------------------------------------------------------------
# _sanitize_object_prefix — path traversal / 위험 입력 차단
# ---------------------------------------------------------------------------


def test_sanitize_prefix_rejects_dotdot_traversal():
    with pytest.raises(ValueError, match="Unsafe path segment"):
        _sanitize_object_prefix("fac_abc/..")


def test_sanitize_prefix_rejects_dotdot_in_middle():
    with pytest.raises(ValueError):
        _sanitize_object_prefix("fac_abc/../../etc")


def test_sanitize_prefix_rejects_single_dot_segment():
    with pytest.raises(ValueError):
        _sanitize_object_prefix("./fac_abc")


def test_sanitize_prefix_rejects_null_byte():
    """object key 가 null byte 를 포함하면 일부 backend 에서 truncation 공격 가능."""
    with pytest.raises(ValueError, match="Invalid characters"):
        _sanitize_object_prefix("fac_abc\x00/etc")


def test_sanitize_prefix_rejects_backslash():
    """Windows 스타일 separator 는 허용 안 함 — S3 key 에선 backslash 가 literal."""
    with pytest.raises(ValueError, match="Invalid characters"):
        _sanitize_object_prefix("fac_abc\\thumbnails")


def test_sanitize_prefix_rejects_empty():
    with pytest.raises(ValueError):
        _sanitize_object_prefix("")


def test_sanitize_prefix_rejects_only_slashes():
    """슬래시만 들어와서 정규화 후 빈 prefix 가 되면 거부."""
    with pytest.raises(ValueError):
        _sanitize_object_prefix("///")


def test_sanitize_prefix_rejects_non_string():
    with pytest.raises(ValueError):
        _sanitize_object_prefix(None)  # type: ignore[arg-type]


def test_sanitize_prefix_rejects_special_characters():
    """공백/특수문자/한글 같이 알파뉴메릭+_-/ 외 문자 거부."""
    for bad in ("fac abc", "fac@abc", "fac+abc", "fac:abc", "한국시설"):
        with pytest.raises(ValueError):
            _sanitize_object_prefix(bad)


def test_sanitize_prefix_rejects_control_characters():
    """탭/개행도 prefix 에 못 들어감."""
    for bad in ("fac\tabc", "fac\nabc"):
        with pytest.raises(ValueError):
            _sanitize_object_prefix(bad)


# ---------------------------------------------------------------------------
# _sanitize_extension
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("jpg", "jpg"),
        ("JPG", "jpg"),
        (".jpg", "jpg"),
        (".JPEG", "jpeg"),
        ("png", "png"),
        ("webp", "webp"),
        ("heic", "heic"),
    ],
)
def test_sanitize_extension_accepts_normal_image_exts(raw, expected):
    assert _sanitize_extension(raw) == expected


@pytest.mark.parametrize(
    "bad",
    [
        "",
        ".",
        "..",
        "jpg/x",  # / 포함 → 거부 → 'jpg' fallback
        "j p g",
        "jp\x00g",
        "verylongextname",  # 8자 초과 → fallback
    ],
)
def test_sanitize_extension_falls_back_to_jpg_for_garbage(bad):
    assert _sanitize_extension(bad) == "jpg"


# ---------------------------------------------------------------------------
# StorageService.upload_file — sanitize 통합 + boto3 호출 검증
# ---------------------------------------------------------------------------


class _FakeS3Client:
    def __init__(self):
        self.put_object_calls = []

    def head_bucket(self, **_):
        return {}

    def create_bucket(self, **_):
        return {}

    def put_bucket_policy(self, **_):
        return {}

    def put_object(self, **kwargs):
        self.put_object_calls.append(kwargs)


@pytest.fixture
def storage_with_mock_s3(monkeypatch):
    """StorageService 를 가짜 S3 client 로 부팅."""
    fake = _FakeS3Client()
    monkeypatch.setattr(storage_module.boto3, "client", lambda *a, **k: fake)
    # 싱글톤 캐시 초기화
    monkeypatch.setattr(storage_module, "_storage", None)
    svc = StorageService()
    return svc, fake


@pytest.mark.asyncio
async def test_upload_file_uses_sanitized_facility_prefix(storage_with_mock_s3):
    svc, fake = storage_with_mock_s3
    key = await svc.upload_file(
        file_data=b"x" * 10,
        filename="photo.JPG",
        content_type="image/jpeg",
        facility_id="fac_abc",
    )
    # 키는 `fac_abc/<uuid hex>.jpg` 형식.
    assert key.startswith("fac_abc/")
    assert key.endswith(".jpg")
    assert len(fake.put_object_calls) == 1
    assert fake.put_object_calls[0]["Key"] == key
    assert fake.put_object_calls[0]["ContentLength"] == 10


@pytest.mark.asyncio
async def test_upload_file_rejects_path_traversal_facility_id(storage_with_mock_s3):
    svc, fake = storage_with_mock_s3
    with pytest.raises(ValueError):
        await svc.upload_file(
            file_data=b"x",
            filename="photo.jpg",
            content_type="image/jpeg",
            facility_id="../../etc",
        )
    # boto3 put_object 까지 가지 않아야 — sanitize 실패 시 호출 자체 차단.
    assert fake.put_object_calls == []


@pytest.mark.asyncio
async def test_upload_file_normalizes_thumbnails_subpath(storage_with_mock_s3):
    """upload_photos 가 `f"{fac}/thumbnails"` 로 호출하는 패턴이 깨지지 않아야."""
    svc, _fake = storage_with_mock_s3
    key = await svc.upload_file(
        file_data=b"x",
        filename="thumb.png",
        content_type="image/png",
        facility_id="fac_abc/thumbnails",
    )
    assert key.startswith("fac_abc/thumbnails/")
    assert key.endswith(".png")


@pytest.mark.asyncio
async def test_upload_file_falls_back_to_jpg_for_unsafe_extension(
    storage_with_mock_s3,
):
    """sanitize 는 ext 의 알파뉴메릭/길이만 보므로 보안 위험 (특수문자/8자 초과)
    이 들어가면 jpg 로 떨어진다. 내용 자체가 이미지인지는 _validate_upload 책임."""
    svc, _fake = storage_with_mock_s3

    # 특수문자 — sanitize 거부 → jpg fallback
    key = await svc.upload_file(
        file_data=b"x",
        filename="weird.b@t",
        content_type="image/jpeg",
        facility_id="fac_abc",
    )
    assert key.endswith(".jpg")

    # 8자 초과 — sanitize 거부 → jpg fallback
    key2 = await svc.upload_file(
        file_data=b"x",
        filename="weird.verylongext",
        content_type="image/jpeg",
        facility_id="fac_abc",
    )
    assert key2.endswith(".jpg")


# ---------------------------------------------------------------------------
# extract_object_key / to_presigned / download_file
# ---------------------------------------------------------------------------


def test_extract_object_key_strips_endpoint_prefix(storage_with_mock_s3):
    svc, _ = storage_with_mock_s3
    full = f"{svc.endpoint_url}/{svc.bucket}/fac_abc/abcdef.jpg"
    assert svc.extract_object_key(full) == "fac_abc/abcdef.jpg"


def test_extract_object_key_handles_internal_minio_url(storage_with_mock_s3):
    """클러스터 내부 minio URL 도 bucket 다음 부분만 떼서 key 로 인식."""
    svc, _ = storage_with_mock_s3
    internal = f"http://minio:9000/{svc.bucket}/fac_xyz/abc.png"
    assert svc.extract_object_key(internal) == "fac_xyz/abc.png"


def test_extract_object_key_treats_plain_key_as_key(storage_with_mock_s3):
    svc, _ = storage_with_mock_s3
    assert svc.extract_object_key("fac_abc/already-a-key.jpg") == "fac_abc/already-a-key.jpg"


def test_extract_object_key_returns_none_for_unrelated_url(storage_with_mock_s3):
    svc, _ = storage_with_mock_s3
    assert svc.extract_object_key("https://other.host/img.jpg") is None


def test_extract_object_key_returns_none_for_empty(storage_with_mock_s3):
    svc, _ = storage_with_mock_s3
    assert svc.extract_object_key("") is None


def test_to_presigned_uses_external_client(monkeypatch, storage_with_mock_s3):
    svc, _ = storage_with_mock_s3

    captured = {}

    class _ExternalClient:
        def generate_presigned_url(self, operation, Params=None, ExpiresIn=None):
            captured.update(
                {"operation": operation, "params": Params, "expires_in": ExpiresIn}
            )
            return f"https://presigned.example/{Params['Key']}?sig=fake"

    svc.external_client = _ExternalClient()
    full = f"{svc.endpoint_url}/{svc.bucket}/fac_abc/key.jpg"
    out = svc.to_presigned(full, expires_in=120)
    assert out.startswith("https://presigned.example/")
    assert captured["params"]["Key"] == "fac_abc/key.jpg"
    assert captured["expires_in"] == 120


def test_to_presigned_returns_original_when_key_extraction_fails(storage_with_mock_s3):
    svc, _ = storage_with_mock_s3
    foreign = "https://other.host/img.jpg"
    assert svc.to_presigned(foreign) == foreign


def test_to_presigned_returns_original_when_signing_raises(storage_with_mock_s3):
    """presigned URL 생성 실패는 호출자에 안 새고 원본 URL 그대로 반환 (best-effort)."""
    svc, _ = storage_with_mock_s3

    class _Boom:
        def generate_presigned_url(self, *_a, **_k):
            raise RuntimeError("kms down")

    svc.external_client = _Boom()
    full = f"{svc.endpoint_url}/{svc.bucket}/fac_abc/key.jpg"
    assert svc.to_presigned(full) == full


# ---------------------------------------------------------------------------
# download_file / delete_file — boto3 래퍼
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_download_file_returns_bytes_on_success(storage_with_mock_s3):
    svc, _ = storage_with_mock_s3
    blob = b"hello world"

    class _Body:
        def read(self):
            return blob

    svc.client = type(
        "C",
        (),
        {"get_object": staticmethod(lambda **_: {"Body": _Body()})},
    )()
    out = await svc.download_file("fac_abc/key.jpg")
    assert out == blob


@pytest.mark.asyncio
async def test_download_file_returns_none_on_error(storage_with_mock_s3):
    svc, _ = storage_with_mock_s3

    def _raise(**_):
        raise RuntimeError("missing")

    svc.client = type("C", (), {"get_object": staticmethod(_raise)})()
    assert await svc.download_file("fac_abc/missing.jpg") is None


@pytest.mark.asyncio
async def test_delete_file_calls_boto3_delete_object(storage_with_mock_s3):
    svc, _ = storage_with_mock_s3
    calls = []

    def _delete(**kwargs):
        calls.append(kwargs)

    svc.client = type("C", (), {"delete_object": staticmethod(_delete)})()
    await svc.delete_file("fac_abc/key.jpg")
    assert calls == [{"Bucket": svc.bucket, "Key": "fac_abc/key.jpg"}]


# ---------------------------------------------------------------------------
# get_storage — 모듈 싱글톤
# ---------------------------------------------------------------------------


def test_get_storage_caches_singleton(monkeypatch):
    monkeypatch.setattr(storage_module.boto3, "client", lambda *a, **k: _FakeS3Client())
    monkeypatch.setattr(storage_module, "_storage", None)

    a = storage_module.get_storage()
    b = storage_module.get_storage()
    assert a is b
