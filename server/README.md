# 기록 보관 서버 (Cloudflare Worker)

- 주소: https://api.dualtimestudio.com
- Worker 이름: hanjul-api, KV 바인딩: KV (hanjul-data)
- 비밀값(Worker 설정에만 있음, 저장소에 없음): KAKAO_REST_KEY, SESSION_SECRET, KAKAO_CLIENT_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, (선택) KAKAO_ADMIN_KEY
- 엔드포인트: /kakao/login, /kakao/callback, /google/login, /google/callback, GET /me, GET·PUT /data, DELETE /account
