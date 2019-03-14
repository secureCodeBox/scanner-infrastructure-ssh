FROM ruby:alpine

WORKDIR /sectools
ADD Gemfile /sectools
ADD Gemfile.lock /sectools

# required for ssh-keyscan
RUN apk --update add openssh-client && apk --update add bash

RUN gem install ssh_scan bundler

RUN apk --update add --virtual build-dependencies ruby-dev build-base && \
    bundle install && \
    apk del build-dependencies && \
    rm -rf /var/cache/apk/*

COPY . /ssh_scan


HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 CMD curl --fail http://localhost:8080/status || exit 1

COPY src/ src/
COPY lib/ lib/

RUN addgroup --system ssh && \
    adduser --system ssh

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

#TODO rmove hardcoded env var
ENV ENGINE_ADDRESS="http://192.168.188.232:8080"
ENV ENGINE_BASIC_AUTH_USER="kermit"
ENV ENGINE_BASIC_AUTH_PASSWORD="a"

LABEL org.opencontainers.image.title="secureCodeBox scanner-webserver-ssh" \
    org.opencontainers.image.description="SSH_Scan integration for secureCodeBox" \
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
