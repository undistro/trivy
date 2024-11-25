FROM alpine:3.20.3
RUN apk --no-cache add ca-certificates git
RUN apk upgrade && rm /var/cache/apk/*
COPY trivy /usr/local/bin/trivy.bin
RUN echo '#!/bin/sh' > /usr/local/bin/trivy && echo 'umask 002 && echo "umask set to $(umask)" && /usr/local/bin/trivy.bin "$@"' >> /usr/local/bin/trivy && chmod +x /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
RUN adduser -u 5000 -D nonroot && addgroup nonroot root
USER 5000
ENTRYPOINT ["trivy"]
