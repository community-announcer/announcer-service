FROM golang:1.10.1-alpine3.7 AS build

RUN apk --no-cache add git
RUN go get -d -v github.com/gin-gonic/gin
ADD . /go/src/github.com/community-announcer/announcer-service
RUN go install github.com/community-announcer/announcer-service

FROM alpine:3.7

RUN apk --no-cache add --update \
  ca-certificates
RUN mkdir /http-server
WORKDIR /http-server

COPY --from=build /go/bin/announcer-service /http-server/announcer-service

CMD "/http-server/announcer-service"
