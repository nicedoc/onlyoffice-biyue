FROM golang:alpine AS build
LABEL maintainer Ascensio System SIA <support@onlyoffice.com>
ENV GO111MODULE=on \
    GOPROXY=https://goproxy.cn,direct
WORKDIR /usr/src/app
COPY . .
RUN go build -o gateway-main services/gateway/main.go
RUN go build -o auth-main services/auth/main.go 
RUN go build -o callback-main services/callback/main.go 
RUN go build -o runner-main services/runner/main.go

FROM golang:alpine AS gateway
WORKDIR /usr/src/app
COPY --from=build \
     /usr/src/app/gateway-main \
     /usr/src/app/main
EXPOSE 4044
CMD ["./main", "server"]

FROM golang:alpine AS auth
WORKDIR /usr/src/app
COPY --from=build \
     /usr/src/app/auth-main \
     /usr/src/app/main
EXPOSE 5069
CMD ["./main", "server"]

FROM golang:alpine AS callback
WORKDIR /usr/src/app
COPY --from=build \
     /usr/src/app/callback-main \
     /usr/src/app/main
EXPOSE 5044
CMD ["./main", "server"]

FROM zenika/alpine-chrome:with-puppeteer AS runner
WORKDIR /usr/src/app
COPY --from=build \
     /usr/src/app/runner-main \
     /usr/src/app/main
EXPOSE 6060
CMD ["./main", "server"]

