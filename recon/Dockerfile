# recon — spider/fingerprint/detect core. Static Go binary.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/recon ./cmd/recon

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/recon /recon
ENTRYPOINT ["/recon"]
