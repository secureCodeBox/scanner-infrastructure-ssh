FROM ruby:alpine

ARG SSH_SCAN_VERSION="0.0.42"

WORKDIR /sectools
ADD Gemfile /sectools
ADD Gemfile.lock /sectools

# required for ssh-keyscan
RUN apk --update add openssh-client && apk --update add bash && \
    rm -rf /var/cache/apk/*

RUN gem install bundler

RUN apk --update add --virtual build-dependencies ruby-dev build-base git && \
    bundle install && \
    apk del build-dependencies && \
    rm -rf /var/cache/apk/*

COPY . /ssh_scan

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 CMD curl --fail http://localhost:8080/status || exit 1

COPY src/ src/

RUN addgroup --system ssh && \
    adduser --system ssh

RUN chgrp -R 0 /ssh_scan/ && \
    chmod -R g=u /ssh_scan/ && \
    chown -R ssh /ssh_scan/

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

ENV SSH_SCAN_VERSION ${SSH_SCAN_VERSION}

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

ENTRYPOINT ["bundle","exec","ruby","./src/main.rb"]
