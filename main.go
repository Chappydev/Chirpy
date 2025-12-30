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
	"github.com/google/uuid"
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

func (cfg *apiConfig) handleCreateChirp(w http.ResponseWriter, r *http.Request) {
  type chirpData struct {
    Body string `json:"body"`
    UserId string `json:"user_id"`
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
    resBody, err := json.Marshal(errorBody{Error: "Chirp is too long"})
    if err == nil {
      w.Write(resBody)
    }
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

  // Save the cleaned chirp
  chirpUUID, err := uuid.Parse(chirp.UserId)
  if err != nil {
    w.WriteHeader(http.StatusBadRequest)
    resBody, err := json.Marshal(errorBody{Error: "invalid uuid for user_id"})
    if err == nil {
      w.Write(resBody)
    }
    return
  }
  savedChirp, err := cfg.queries.CreateChirp(r.Context(), database.CreateChirpParams{Body: cleanedBody, UserID: chirpUUID})
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
  }

  chirpJSON, err := json.Marshal(savedChirp)
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    log.Print(err)
  }

  // Write response
  w.WriteHeader(http.StatusCreated)
  w.Write(chirpJSON)
}

func (cfg *apiConfig) handleGetAllChirps(w http.ResponseWriter, r *http.Request) {
  allChirps, err := cfg.queries.GetAllChirps(r.Context())
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    log.Printf("[GET /api/chirps] Fail to fetch chirps: %v\n", err)
    return
  }

  jsonChirps, err := json.Marshal(allChirps)
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    log.Printf("[GET /api/chirps] Fail to marshal chirps: %v\n", err)
    return
  }

  w.WriteHeader(http.StatusOK)
  w.Write(jsonChirps)
}

func (cfg *apiConfig) handleChirpByID(w http.ResponseWriter, r *http.Request) {
  chirpIDString := r.PathValue("chirpID")
  chirpID, err := uuid.Parse(chirpIDString)
  if err != nil {
    w.WriteHeader(http.StatusBadRequest)
    resBody, err := json.Marshal(errorBody{Error: "Invalid id"})
    if err == nil {
      w.Write(resBody)
    }
    return
  }

  matchingChirp, err := cfg.queries.GetChirpByID(r.Context(), chirpID)
  if err != nil {
    w.WriteHeader(http.StatusNotFound)
    log.Printf("[GET /api/chirps{chirpID}] Fail to fetch chirp: %v\n", err)
    return
  }

  jsonChirp, err := json.Marshal(matchingChirp)
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    log.Printf("[GET /api/chirps/{chirpID}] Fail to marshal chirp: %v\n", err)
    return
  }

  w.WriteHeader(http.StatusOK)
  w.Write(jsonChirp)
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
  mux.HandleFunc("POST /api/chirps", apiCfg.handleCreateChirp)
  mux.HandleFunc("GET /api/healthz", handleHealthz)
  mux.HandleFunc("POST /api/users", apiCfg.handleCreateUser)
  mux.HandleFunc("GET /api/chirps", apiCfg.handleGetAllChirps)
  mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handleChirpByID)

  // Server config
  server := &http.Server{
    Addr: ":" + port, 
    Handler: mux,
  }

  log.Printf("Server running on port %s\n", port)
  log.Fatal(server.ListenAndServe())
}
