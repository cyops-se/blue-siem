// Package api exposes the REST API, the SSE live stream and the embedded
// frontend.
package api

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"gorm.io/gorm"

	"blue-siem/internal/engine"
	"blue-siem/internal/models"
)

type Info struct {
	SyslogUDP string `json:"syslog_udp"`
	SyslogTCP string `json:"syslog_tcp"`
	Version   string `json:"version"`
}

type Server struct {
	db   *gorm.DB
	eng  *engine.Engine
	info Info
}

func NewRouter(db *gorm.DB, eng *engine.Engine, info Info, web fs.FS) http.Handler {
	s := &Server{db: db, eng: eng, info: info}
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	r.Route("/api", func(r chi.Router) {
		r.Get("/stats", s.stats)
		r.Get("/stream", s.stream)

		r.Get("/events", s.listEvents)
		r.Get("/events/{id}", s.getEvent)
		r.Delete("/events", s.clearEvents)

		r.Get("/flows", s.listFlows)
		r.Delete("/flows", s.clearFlows)

		r.Get("/alarms", s.listAlarms)
		r.Post("/alarms/ack", s.ackAlarms)
		r.Post("/alarms/{id}/ack", s.ackAlarm)

		r.Get("/decoders", list[models.Decoder](s, "priority, id"))
		r.Post("/decoders", create(s, validateDecoder))
		r.Post("/decoders/test", s.testDecoder)
		r.Put("/decoders/{id}", update(s, validateDecoder))
		r.Delete("/decoders/{id}", remove[models.Decoder](s))

		r.Get("/rules", list[models.SeverityRule](s, "priority, id"))
		r.Post("/rules", create(s, validateRule))
		r.Put("/rules/{id}", update(s, validateRule))
		r.Delete("/rules/{id}", remove[models.SeverityRule](s))

		r.Get("/iplists", list[models.IPListEntry](s, "list, cidr"))
		r.Post("/iplists", create(s, validateIPEntry))
		r.Put("/iplists/{id}", update(s, validateIPEntry))
		r.Delete("/iplists/{id}", remove[models.IPListEntry](s))

		r.Get("/settings", s.getSettings)
		r.Put("/settings", s.putSettings)

		r.Post("/test", s.test)
		r.Post("/ingest", s.ingest)

		r.NotFound(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotFound, "not found")
		})
	})

	r.Handle("/*", spa(web))
	return r
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	return dec.Decode(v)
}

func idParam(r *http.Request) (uint, error) {
	n, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	return uint(n), err
}

func intQuery(r *http.Request, key string, def, min, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

// reload recompiles the engine after configuration changes.
func (s *Server) reload(w http.ResponseWriter) bool {
	if err := s.eng.Reload(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	return true
}

// Generic CRUD handlers for the configuration resources.

func list[T any](s *Server, order string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		items := []T{}
		if err := s.db.Order(order).Find(&items).Error; err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, items)
	}
}

func create[T any](s *Server, validate func(*T) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var item T
		if err := readJSON(r, &item); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := validate(&item); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.db.Create(&item).Error; err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if s.reload(w) {
			writeJSON(w, http.StatusCreated, item)
		}
	}
}

func update[T any](s *Server, validate func(*T) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := idParam(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid id")
			return
		}
		var item T
		if err := readJSON(r, &item); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := validate(&item); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		res := s.db.Model(new(T)).Where("id = ?", id).Select("*").Omit("id", "created_at").Updates(&item)
		if res.Error != nil {
			writeError(w, http.StatusBadRequest, res.Error.Error())
			return
		}
		if res.RowsAffected == 0 {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		var saved T
		s.db.First(&saved, id)
		if s.reload(w) {
			writeJSON(w, http.StatusOK, saved)
		}
	}
}

func remove[T any](s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := idParam(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid id")
			return
		}
		if err := s.db.Delete(new(T), id).Error; err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if s.reload(w) {
			w.WriteHeader(http.StatusNoContent)
		}
	}
}

// spa serves the embedded frontend and falls back to index.html so that
// client side routes survive a reload.
func spa(web fs.FS) http.Handler {
	files := http.FileServer(http.FS(web))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" || p == "index.html" {
			serveIndex(w, web)
			return
		}
		if _, err := fs.Stat(web, p); errors.Is(err, fs.ErrNotExist) {
			serveIndex(w, web)
			return
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, r)
	})
}

func serveIndex(w http.ResponseWriter, web fs.FS) {
	b, err := fs.ReadFile(web, "index.html")
	if err != nil {
		http.Error(w, "frontend not built", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(b)
}
