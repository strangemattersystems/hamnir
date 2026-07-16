# syntax=docker/dockerfile:1

FROM golang:1.26 AS build

WORKDIR /src

COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 go build -trimpath -tags netgo,osusergo -ldflags="-s -w" -o /out/hamnir ./cmd/hamnir

# ---

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /home/nonroot

COPY --from=build /out/hamnir /usr/local/bin/hamnir

EXPOSE 5556

ENTRYPOINT ["hamnir"]

CMD ["serve", "--addr", "0.0.0.0:5556"]
