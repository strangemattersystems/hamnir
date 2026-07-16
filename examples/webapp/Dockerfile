# syntax=docker/dockerfile:1

FROM golang:1.26 AS build

WORKDIR /src

COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 go build -trimpath -tags netgo,osusergo -ldflags="-s -w" -o /out/webapp .

# ---

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/webapp /usr/local/bin/webapp

EXPOSE 8080

ENTRYPOINT ["webapp"]
