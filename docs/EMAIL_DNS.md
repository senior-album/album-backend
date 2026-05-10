# 이메일 발송 도메인 DNS 셋업 (Brevo)

T-305 (roadmap#228). Brevo Transactional Email API 로 발송하는 메일이 수신자
받은편지함 (스팸함 X) 에 도달하려면 발송 도메인의 SPF / DKIM / DMARC 레코드를
1회 셋업해야 한다. 도메인은 senior-album 이 보유한 도메인 (Cloudflare DNS 관리)
을 가정.

## 1. Brevo 계정 + 도메인 인증

1. https://app.brevo.com 가입
2. **Senders, Domains & Dedicated IPs** → **Domains** → **Add a domain**
3. 발송 도메인 입력 (예: `senior-album.com` 또는 메일 전용 서브도메인 `mail.senior-album.com`)
4. Brevo 가 표시하는 DNS 레코드 3개 확인:
   - SPF (TXT)
   - DKIM (TXT, 선택자 = `mail._domainkey` 등)
   - Brevo Code (TXT, 도메인 소유 검증용 1회용)

## 2. Cloudflare DNS 에 레코드 추가

Cloudflare 대시보드 → 해당 도메인 → **DNS** → **Records** → **Add record**:

| Type | Name | Content | Proxy | TTL |
|---|---|---|---|---|
| TXT | `@` (또는 서브도메인) | `v=spf1 include:spf.brevo.com ~all` | DNS only | Auto |
| TXT | `mail._domainkey` (Brevo 가 알려주는 선택자) | Brevo 가 제공하는 긴 base64 키 | DNS only | Auto |
| TXT | (Brevo 가 알려주는 임의 host) | Brevo 가 제공하는 검증 코드 | DNS only | Auto |

> Cloudflare proxy (orange cloud) 는 끄기 — TXT 레코드는 DNS only.

## 3. DMARC (선택, 권장)

DMARC 는 SPF/DKIM 검증 실패 시 메일을 어떻게 처리할지 수신서버에 지시.
없으면 일부 ISP 가 의심 메일로 분류할 수 있음.

| Type | Name | Content |
|---|---|---|
| TXT | `_dmarc` | `v=DMARC1; p=none; rua=mailto:dmarc@senior-album.com` |

`p=none` 은 모니터링만 (메일은 통과). 운영 안정 후 `p=quarantine` →
`p=reject` 로 단계적 강화.

## 4. Brevo 에서 검증

도메인 페이지로 돌아가 **Authenticate this domain** → 검증 통과 (보통 5–15분).
실패하면 DNS 전파 대기 (`dig TXT mail._domainkey.senior-album.com @1.1.1.1` 로
확인).

## 5. 발송 주소 결정 + 환경변수 셋업

도메인 인증 후 그 도메인의 임의 주소를 `BREVO_FROM_EMAIL` 로 사용 가능.
권장: `noreply@senior-album.com` 또는 `support@senior-album.com`.

운영 SealedSecret 갱신:

```bash
# album-deploy 에서
cd album-deploy
echo -n "<brevo-api-key>" | kubectl create secret generic backend-secret \
    --from-file=BREVO_API_KEY=/dev/stdin --dry-run=client -o yaml \
    | kubeseal --merge-into k8s/sealed/backend-secret.yaml
```

또한 `k8s/backend.yaml` 의 `env:` 에 평문 envvar 3개 추가:
- `EMAIL_PROVIDER=brevo`
- `BREVO_FROM_EMAIL=noreply@senior-album.com`
- `BREVO_FROM_NAME=Senior Album`

`BREVO_API_KEY` 만 SealedSecret. 나머지는 ConfigMap / 평문 env (시크릿 아님).

## 6. 테스트 발송

배포 후 backend pod 안에서:

```python
from app.services.email import get_email_provider
import asyncio
asyncio.run(get_email_provider().send(
    to="<your-test-address>",
    subject="[Senior Album] Brevo 테스트",
    html="<p>이 메일은 운영 환경 도달성 검증용입니다.</p>",
))
```

받은편지함 (스팸함 X) 도달 확인. 헤더의 `Authentication-Results` 에
`spf=pass`, `dkim=pass`, `dmarc=pass` 가 모두 떠야 정상.

## 트러블슈팅

- **메일이 스팸함**: 대부분 SPF / DKIM 미검증. Cloudflare 의 TXT 레코드 값과
  Brevo 의 안내값이 정확히 일치하는지 재확인 (공백 / 따옴표 주의)
- **`Brevo 발송 실패 (status=400)` 로그**: `BREVO_FROM_EMAIL` 도메인이 Brevo
  대시보드에서 인증 안 된 상태. 1단계 재확인
- **`Brevo 발송 실패 (status=401)`**: API key 가 만료/철회됨. 새 키 발급 후
  SealedSecret 갱신
- **`Brevo 발송 실패 (status=429)`**: 일 300통 무료 한도 초과 (월 ~9000).
  유료 전환 또는 다음 일 자동 리셋 대기
