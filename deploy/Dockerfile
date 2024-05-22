FROM alpine:latest as builder
RUN apk add --no-cache git
WORKDIR /app
RUN git clone https://github.com/nicedoc/onlyoffice.github.io .

FROM alpine:latest AS plugin
ENV PLUGIN_DIR=/var/www/onlyoffice/documentserver/sdkjs-plugins/biyue

COPY --from=builder /app/sdkjs-plugins/content/biyue /biyue

ENTRYPOINT ["sh"]
CMD ["-c", "mkdir -p ${PLUGIN_DIR} && rm -rf {PLUGIN_DIR}/* && cp -r /biyue/* ${PLUGIN_DIR} && tail -f /dev/null"]
