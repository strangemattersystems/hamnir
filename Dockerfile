# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

FROM golang:1.27@sha256:512690a5660563b57d37ecc31129e7f136e831db2aed24a1dbeb8ad7380dc0fa AS build

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

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

WORKDIR /home/nonroot

COPY --from=build /out/hamnir /usr/local/bin/hamnir

ENV HAMNIR_ADDR=0.0.0.0:5556

EXPOSE 5556

ENTRYPOINT ["hamnir"]

CMD ["serve"]
