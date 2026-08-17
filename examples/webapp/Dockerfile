# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

FROM golang:1.26@sha256:0d1d3a794be25f809dd2cb3160d8c73276c4056a9f8242a138e908ddeee7b6b6 AS build

WORKDIR /src

COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 go build -trimpath -tags netgo,osusergo -ldflags="-s -w" -o /out/webapp .

# ---

FROM gcr.io/distroless/static-debian12:nonroot@sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a

COPY --from=build /out/webapp /usr/local/bin/webapp

EXPOSE 8080

ENTRYPOINT ["webapp"]
