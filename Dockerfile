# syntax=docker/dockerfile:1
FROM golang:1.27.2-alpine AS build

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/incidentpilot ./cmd/incidentpilot

FROM scratch
COPY --from=build /out/incidentpilot /incidentpilot
USER 65532:65532
ENV INCIDENTPILOT_ADDR=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/incidentpilot"]
