FROM ruby:alpine
WORKDIR /sectools/

RUN wget https://github.com/mozilla/ssh_scan_api/archive/master.tar.gz -P /sectools && \
    tar zxvf /sectools/master.tar.gz -C /sectools && \
    rm /sectools/master.tar.gz

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 CMD curl --fail http://localhost:8080/status || exit 1

COPY Gemfile src/

RUN bundle install --gemfile=/sectools/src/Gemfile

COPY src/ src/
COPY lib/ lib/

RUN addgroup -system ssh && \
    adduser -system ssh && \
    usermod -g ssh ssh

RUN chgrp -R 0 /sectools/ && \
    chmod -R g=u /sectools/ && \
    chown -R ssh /sectools/

USER ssh

EXPOSE 8080

ARG COMMIT_ID=unkown
ARG REPOSITORY_URL=unkown
ARG BRANCH=unkown
ARG BUILD_DATE
ARG VERSION

ENV SCB_COMMIT_ID ${COMMIT_ID}
ENV SCB_REPOSITORY_URL ${REPOSITORY_URL}
ENV SCB_BRANCH ${BRANCH}

LABEL org.opencontainers.image.title="secureCodeBox scanner-webserver-nikto" \
    org.opencontainers.image.description="Nikto integration for secureCodeBox" \
    org.opencontainers.image.authors="iteratec GmbH" \
    org.opencontainers.image.vendor="iteratec GmbH" \
    org.opencontainers.image.documentation="https://github.com/secureCodeBox/secureCodeBox" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.version=$VERSION \
    org.opencontainers.image.url=$REPOSITORY_URL \
    org.opencontainers.image.source=$REPOSITORY_URL \
    org.opencontainers.image.revision=$COMMIT_ID \
    org.opencontainers.image.created=$BUILD_DATE

ENTRYPOINT ["bash","/sectools/src/starter.sh"]
