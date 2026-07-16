# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

FROM golang:1.26@sha256:ae5a2316d12f3e78fd99177dad452e6ad4f240af2d71d57b480c3477f250fec6 AS build

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

FROM gcr.io/distroless/static-debian12:nonroot@sha256:aef9602f8710ec12bde19d593fed1f76c708531bb7aba205110f1029786ead7b

WORKDIR /home/nonroot

COPY --from=build /out/hamnir /usr/local/bin/hamnir

EXPOSE 5556

ENTRYPOINT ["hamnir"]

CMD ["serve", "--addr", "0.0.0.0:5556"]
