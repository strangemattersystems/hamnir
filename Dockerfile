# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

FROM golang:1.26@sha256:0d1d3a794be25f809dd2cb3160d8c73276c4056a9f8242a138e908ddeee7b6b6 AS build

WORKDIR /src

COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY . .

ARG VERSION=0.0.0-dev
ARG REVISION=unknown
ARG DATE=unknown

RUN CGO_ENABLED=0 go build -trimpath -tags netgo,osusergo \
	-ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION} -X main.date=${DATE}" \
	-o /out/hamnir ./cmd/hamnir

# ---

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35

WORKDIR /home/nonroot

COPY --from=build /out/hamnir /usr/local/bin/hamnir

ENV HAMNIR_ADDR=0.0.0.0:5556

EXPOSE 5556

ENTRYPOINT ["hamnir"]

CMD ["serve"]
