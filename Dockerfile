# FROM golang:1.14-alpine AS builder
# WORKDIR /go/src/github.com/msiedlarek/nifi_exporter
# COPY . .
# RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o /go/bin/nifi_exporter

# FROM scratch
# COPY --from=builder /go/bin/nifi_exporter /nifi_exporter
# ENTRYPOINT ["/nifi_exporter"]
# CMD ["/config/config.yml"]



######################################################################################
###### https://stackoverflow.com/questions/47837149/build-docker-with-go-app-cannot-find-package
######################################################################################
# Two-stage build:
#    first  FROM prepares a binary file in full environment ~780MB
#    second FROM takes only binary file ~10MB

FROM golang:1.9 AS builder

RUN go version

COPY . "/go/src/github.com/MsAPotter/nifi_exporter"
WORKDIR "/go/src/github.com/MsAPotter/nifi_exporter"

#RUN go get -v -t  .
RUN set -x && \
    #go get github.com/2tvenom/go-test-teamcity && \  
    go get github.com/golang/dep/cmd/dep && \
    dep ensure -v

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build  -o /nifi_exporter


EXPOSE 8000

ENTRYPOINT ["/nifi_exporter/nifi/client/client.go"]
CMD ["/config/config.yml"]



#########
# second stage to obtain a very small image

# FROM scratch

# COPY --from=builder /your-app .

#EXPOSE 8000

# ENTRYPOINT ["/nifi_exporter"]
# CMD ["/config/config.yml"]

