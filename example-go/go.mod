module example-go-oidc-redis

go 1.21

// Sample này nằm cạnh source library; replace để build dùng code local
// thay vì proxy. Khi tách hẳn ra repo riêng, bỏ replace và `go get`
// version đã publish.
replace github.com/strongnguyen29/go-oidc-provider => ../go-oidc-provider

require github.com/strongnguyen29/go-oidc-provider v0.0.0-00010101000000-000000000000

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/go-chi/chi/v5 v5.0.12 // indirect
	github.com/go-jose/go-jose/v4 v4.0.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/redis/go-redis/v9 v9.7.0 // indirect
	golang.org/x/crypto v0.19.0 // indirect
)
