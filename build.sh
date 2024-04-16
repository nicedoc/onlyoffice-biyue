go env -w GO111MODULE=on
go env -w GOPROXY=https://goproxy.cn,direct
cd /Users/henrik/dev/onlyoffice-biyue
CGO_ENABLE=0 GOOS=linux GOARCH=arm64 go build -o build/gateway services/gateway/main.go
CGO_ENABLE=0 GOOS=linux GOARCH=arm64 go build -o build/callback services/callback/main.go
CGO_ENABLE=0 GOOS=linux GOARCH=arm64 go build -o build/auth services/auth/main.go
cd /Users/henrik/dev/onlyoffice-biyue/local-env
docker-compose build

