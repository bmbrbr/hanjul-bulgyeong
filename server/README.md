# 기록 보관 서버 (Cloudflare Worker)

- 주소: https://api.dualtimestudio.com
- Worker 이름: hanjul-api, KV 바인딩: KV (hanjul-data)
- 비밀값(Worker 설정에만 있음, 저장소에 없음): KAKAO_REST_KEY, SESSION_SECRET, (선택) KAKAO_ADMIN_KEY, KAKAO_CLIENT_SECRET
- 엔드포인트: /kakao/login, /kakao/callback, GET /me, GET·PUT /data, DELETE /account
