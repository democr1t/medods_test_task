# Build stage
FROM golang:latest as builder

WORKDIR /app

COPY . .

RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/auth-api ./cmd/main.go

# Run stage
FROM alpine:3.18
RUN apk --no-cache add ca-certificates libc6-compat

WORKDIR /
COPY --from=builder /bin/auth-api /auth-api
RUN chmod +x /auth-api

EXPOSE 8080
CMD ["/auth-api"]