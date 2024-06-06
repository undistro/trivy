FROM alpine:3.19.1
RUN apk --no-cache add ca-certificates git
RUN apk upgrade && rm /var/cache/apk/*
COPY trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
RUN adduser -u 5000 -D nonroot && addgroup nonroot root
USER 5000
RUN umask 002
ENTRYPOINT ["trivy"]
