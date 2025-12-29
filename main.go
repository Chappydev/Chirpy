package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
  fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    cfg.fileserverHits.Add(1)
    next.ServeHTTP(w, r)
  })
}

func (cfg *apiConfig) handleMetrics(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "text/html")
  w.WriteHeader(200)
  bodyHTML := fmt.Sprintf(
`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, 
    cfg.fileserverHits.Load())
  w.Write([]byte(bodyHTML))
}

func (cfg *apiConfig) handleReset(w http.ResponseWriter, r *http.Request) {
  cfg.fileserverHits.Store(0)
  w.WriteHeader(200)
}

func main() {
  port := "8080"

  apiCfg := &apiConfig{}
  mux := http.NewServeMux()
  
  // Handlers
  mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
  mux.HandleFunc("GET /admin/metrics", apiCfg.handleMetrics)
  mux.HandleFunc("POST /admin/reset", apiCfg.handleReset)
  mux.HandleFunc("POST /api/validate_chirp", func(w http.ResponseWriter, r *http.Request) {
    type chirpData struct {
      Body string `json:"body"`
    }

    type validity struct {
      Valid bool `json:"valid"`
    }

    w.Header().Add("Content-Type", "application/json")

    decoder := json.NewDecoder(r.Body)
    var chirp chirpData
    if err := decoder.Decode(&chirp); err != nil {
      w.WriteHeader(400)
      w.Write([]byte("{\"error\": \"failed to parse request body as json\"}"))
      return
    }

    if len(chirp.Body) > 140 {
      w.WriteHeader(400)
      w.Write([]byte("{\"error\": \"Chirp is too long\"}"))
      return
    }

    isValid := validity{
      Valid: true,
    }
    isValidJSON, err := json.Marshal(isValid)
    if err != nil {
      w.WriteHeader(500)
      w.Write([]byte("{\"error\": \"failed to marshal the response\"}"))
      return
    }
    w.Write(isValidJSON)
    w.WriteHeader(400)
  })
  mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Add("Content-Type", "text/plain; charset=utf-8")
    w.WriteHeader(200)
    w.Write([]byte("OK"))
  })

  server := &http.Server{
    Addr: ":" + port, 
    Handler: mux,
  }

  log.Printf("Server running on port %s\n", port)
  log.Fatal(server.ListenAndServe())
}
