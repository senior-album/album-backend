# CoolSMS 실 연동 런북

휴대폰 OTP 발송을 **프로덕션 SMS** 로 전환하는 절차. 현재는 `SMS_PROVIDER=log` 가 기본이라 인증번호가 서버 로그에만 출력된다.

## 1. CoolSMS 계정·발신번호 등록

CoolSMS 는 개인·법인 모두 사용 가능하지만, **발신번호 사전등록이 필수**다 (정보통신망법 준수). 등록하지 않은 번호로 발송 시도 시 403 반환.

1. https://coolsms.co.kr 가입 → 로그인
2. **콘솔 → 발신번호 관리** → "발신번호 등록" 클릭
3. 인증 방법 선택:
   - **개인 본인인증** (SMS 로 받은 코드 입력) — 당일 처리
   - **서류 제출** — 법인 또는 대리인 등록 시 필요
     - 통신서비스 이용증명원 (해당 번호 발급 통신사에서 발급) 또는
     - 사업자등록증 + 대표자 신분증
     - 서류 영업일 1~2일 심사
4. 등록 후 **"발신 가능 번호 목록"** 에 표시되면 완료
5. 승인된 번호를 `.env` 에 `COOLSMS_FROM_NUMBER` 로 저장 — 반드시 등록된 번호여야 하며 오타 시 발송 실패

> MVP 초기엔 창업자 개인 휴대폰을 등록해도 된다. 단 SMS 수신 문자에 "발신번호" 가 그 번호로 찍힌다는 점을 고려.

## 2. API 키 발급

1. CoolSMS 콘솔 → **개발자 센터 → API Key 관리**
2. "새 키 발급" — 권한은 **"메세지 발송"** 만 체크 (최소 권한)
3. `API_KEY` 와 `API_SECRET` 저장 → `.env`
   - **API_SECRET 은 발급 직후 한 번만 노출**된다. 놓치면 재발급 필요.

## 3. 환경변수

`.env` (로컬) 또는 k8s Secret (프로덕션):

```
SMS_PROVIDER=coolsms
COOLSMS_API_KEY=<발급된 키>
COOLSMS_API_SECRET=<발급된 시크릿>
COOLSMS_FROM_NUMBER=01012345678       # 반드시 발신번호 등록된 번호, 하이픈 없이 숫자만
```

> 프로덕션에서는 **Sealed Secrets** 또는 SOPS 로 암호화해 매니페스트에 커밋 (T-050, T-055 참조). 평문 k8s Secret 으로 올리지 말 것.

## 4. SDK 또는 HTTP 클라이언트 선택

### 옵션 A — 공식 SDK (`coolsms_python_sdk`)

```
pip install coolsms-python-sdk
```

`app/services/sms.py` 의 `CoolSmsProvider.send` 구현:

```python
from sdk.api.message import Message
from sdk.exceptions import CoolsmsException

async def send(self, phone: str, message: str) -> None:
    s = get_settings()
    try:
        cool = Message(s.COOLSMS_API_KEY, s.COOLSMS_API_SECRET)
        params = {
            "type": "sms",               # 90바이트 이하 (OTP 에 충분)
            "to": phone,
            "from": s.COOLSMS_FROM_NUMBER,
            "text": message,
        }
        cool.send(params)
    except CoolsmsException as e:
        logger.error(f"CoolSMS send failed: {e.code} {e.msg}")
        raise
```

SDK 는 동기 호출이라 `asyncio.to_thread` 로 감싸는 것 권장 (라이브러리 내부에서 requests 사용).

### 옵션 B — REST API 직접 호출 (SDK 미사용)

CoolSMS 4.x API 는 HMAC 서명 기반이다. 간단한 경우 `httpx` + 서명 생성 헬퍼로 대체 가능. SDK 가 `requests` 에만 의존해 async 충돌이 걱정될 때 선택.

요점:
- Endpoint: `POST https://api.coolsms.co.kr/messages/v4/send`
- Header: `Authorization: HMAC-SHA256 apiKey=<k>, date=<ISO>, salt=<rand>, signature=<hex>`
- 서명: `HMAC_SHA256(secret, date + salt)` 를 hex 인코딩

## 5. 비용

2026-04 기준 (변동 가능, 공식 요금표 확인 필수):
- **SMS (90바이트 이하)**: 건당 ≈ 20원
- **LMS (2000바이트 이하)**: 건당 ≈ 40원
- **카카오 알림톡**: 건당 ≈ 7~10원 (비즈메시지 채널·템플릿 사전 승인 필요 — T-061)

OTP 는 SMS 로 충분하다. 알림톡은 사진 도착 알림 등 트래픽이 높고 정형화된 메시지에 적합.

**예산 가이드** — 월 보호자 신규 가입 100명, 평균 2회 재시도 가정 시: 약 200건 × 20원 = **4,000원/월**. 거의 무시 가능.

잔액 충전: CoolSMS 콘솔 → 포인트 충전 (최소 1,000원, 카드·계좌이체).

## 6. 전환 절차

1. Staging 환경에서 `SMS_PROVIDER=coolsms` 먼저 적용, 개발자 본인 번호로 발송 테스트
2. OTP 발송 로그 (`[SMS:coolsms]`) + CoolSMS 콘솔의 **발송 이력** 대조
3. 잔액 알림 임계값 설정 (콘솔 → 알림 설정) — 포인트 소진 시 발송 실패
4. 프로덕션 환경변수 교체
5. 배포 후 실제 보호자 계정으로 엔드투엔드 검증

## 7. 장애 대비

- **CoolSMS API 장애 시**: `send_otp` 가 예외 발생 → `/auth/phone/otp/send` 가 500 반환. 현재 구조는 Redis 에만 코드 저장하고 "나중에 발송" 재시도는 하지 않음 — 사용자가 그냥 재요청하면 됨.
- **발신번호 등록 실효**: CoolSMS 측에서 번호 재검증을 요구하는 경우 있음 (1년 단위). 만료 알림 수신 시 재인증 필요.
- **장기 모니터링**: Grafana + Loki 에 `[SMS:coolsms]` 로그 metric 화 (T-042 시 함께).

## 8. 알림톡 전환 검토 (후속)

T-061 에서 비즈니스 채널 개설 + 알림톡 템플릿 심사 완료 시, OTP 채널도 알림톡으로 전환 가능. 장점: 건당 비용 절반 수준, 카카오 앱 내에서 바로 확인. 단점: 카카오톡 미사용자는 알림톡 수신 불가 → SMS fallback 필요.

실제 전환 시 `SmsProvider` 와 병행하는 `AlimTalkProvider` 를 만들고, OTP 서비스에서 "알림톡 우선, 실패 시 SMS" 로 분기.
