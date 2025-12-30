package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/Chappydev/Chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
  fileserverHits atomic.Int32
  queries *database.Queries
  platform string
}

type errorBody struct {
  Error string `json:"error"`
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

func handleValidation(w http.ResponseWriter, r *http.Request) {
  type chirpData struct {
    Body string `json:"body"`
  }

  type validity struct {
    CleanedBody string `json:"cleaned_body"`
  }

  w.Header().Add("Content-Type", "application/json")

  decoder := json.NewDecoder(r.Body)
  var chirp chirpData
  if err := decoder.Decode(&chirp); err != nil {
    w.WriteHeader(400)
    w.Write([]byte("{\"error\": \"failed to parse request body as json\"}"))
    return
  }

  // Validate body length
  if len(chirp.Body) > 140 {
    w.WriteHeader(400)
    w.Write([]byte("{\"error\": \"Chirp is too long\"}"))
    return
  }

  // Clean bad words from the body
  badWords := []string{"kerfuffle", "sharbert", "fornax"}
  
  words := strings.Split(chirp.Body, " ")
  for i, word := range words {
    finalWord := word
    if slices.Contains(badWords, strings.ToLower(word)) {
      finalWord = "****"
    }
    words[i] = finalWord
  }
  cleanedBody := strings.Join(words, " ")

  // Create response body
  isValid := validity{
    CleanedBody: cleanedBody,
  }
  isValidJSON, err := json.Marshal(isValid)
  if err != nil {
    w.WriteHeader(500)
    w.Write([]byte("{\"error\": \"failed to marshal the response\"}"))
    return
  }

  // Write response
  w.WriteHeader(200)
  w.Write(isValidJSON)
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("Content-Type", "text/plain; charset=utf-8")
  w.WriteHeader(200)
  w.Write([]byte("OK"))
}

func (cfg *apiConfig) handleReset(w http.ResponseWriter, r *http.Request) {
  // Check that we are in dev environment
  if cfg.platform != "dev" {
    w.WriteHeader(http.StatusForbidden)
  }

  // Reset metrics
  cfg.fileserverHits.Store(0)

  // Reset database
  err := cfg.queries.DeleteAllUsers(r.Context())
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    resBody, err := json.Marshal(errorBody{Error: err.Error()})
    if err == nil {
      w.Write(resBody)
    }
    return
  }

  w.WriteHeader(200)
}

func (cfg *apiConfig) handleCreateUser(w http.ResponseWriter, r *http.Request) {
  type NewUserParams struct {
    Email string `json:"email"`
  }

  decoder := json.NewDecoder(r.Body)
  userParams := &NewUserParams{}
  if err := decoder.Decode(userParams); err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    resBody, err := json.Marshal(errorBody{Error: err.Error()})
    if err == nil {
      w.Write(resBody)
    }
    return
  }

  user, err := cfg.queries.CreateUser(r.Context(), userParams.Email)
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    resBody, err := json.Marshal(errorBody{Error: err.Error()})
    if err == nil {
      w.Write(resBody)
    }
    return
  }

  resBody, err := json.Marshal(user)
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    resBody, err := json.Marshal(errorBody{Error: err.Error()})
    if err == nil {
      w.Write(resBody)
    }
    return
  }

  w.WriteHeader(http.StatusCreated)
  w.Header().Add("Content-Type", "application/json")
  w.Write(resBody)
}

func main() {
  port := "8080"

  apiCfg := &apiConfig{}
  mux := http.NewServeMux()

  godotenv.Load()
  
  apiCfg.platform = os.Getenv("PLATFORM")

  // Set up database queries
  dbUrl := os.Getenv("DB_URL")
  db, err := sql.Open("postgres", dbUrl)
  if err != nil {
    log.Fatal(err)
  }
  apiCfg.queries = database.New(db)
  
  // Handlers
  mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
  mux.HandleFunc("GET /admin/metrics", apiCfg.handleMetrics)
  mux.HandleFunc("POST /admin/reset", apiCfg.handleReset)
  mux.HandleFunc("POST /api/validate_chirp", handleValidation)
  mux.HandleFunc("GET /api/healthz", handleHealthz)
  mux.HandleFunc("POST /api/users", apiCfg.handleCreateUser)

  // Server config
  server := &http.Server{
    Addr: ":" + port, 
    Handler: mux,
  }

  log.Printf("Server running on port %s\n", port)
  log.Fatal(server.ListenAndServe())
}
