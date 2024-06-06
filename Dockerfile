FROM alpine:3.19.1
RUN apk --no-cache add ca-certificates git
RUN apk upgrade && rm /var/cache/apk/*
COPY trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
RUN adduser -u 5000 -D nonroot && addgroup nonroot root
USER 5000
RUN sed -i -e 's+^umask [0-7]*+umask 002+' /etc/profile
ENTRYPOINT ["trivy"]
