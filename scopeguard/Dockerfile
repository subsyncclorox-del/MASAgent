# scopeguard — the network gate. Static Go binary in a scratch image.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/scopeguard ./cmd/scopeguard

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/scopeguard /scopeguard
EXPOSE 8898 8899
ENTRYPOINT ["/scopeguard"]
