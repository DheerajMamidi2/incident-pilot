package webui

import (
	"bytes"
	"embed"
	"net/http"
	"time"
)

//go:embed static/index.html static/styles.css static/app.js
var assets embed.FS

type Handler struct{}

func NewHandler() Handler { return Handler{} }

func (Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		response.Header().Set("Allow", "GET, HEAD")
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := ""
	contentType := ""
	cacheControl := "public, max-age=3600"
	switch request.URL.Path {
	case "/", "/index.html":
		path = "static/index.html"
		contentType = "text/html; charset=utf-8"
		cacheControl = "no-store"
	case "/assets/styles.css":
		path = "static/styles.css"
		contentType = "text/css; charset=utf-8"
	case "/assets/app.js":
		path = "static/app.js"
		contentType = "text/javascript; charset=utf-8"
	default:
		http.NotFound(response, request)
		return
	}
	content, err := assets.ReadFile(path)
	if err != nil {
		http.Error(response, "asset unavailable", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", contentType)
	response.Header().Set("Cache-Control", cacheControl)
	http.ServeContent(response, request, path, time.Time{}, bytes.NewReader(content))
}
