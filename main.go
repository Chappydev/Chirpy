package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Chappydev/Chirpy/internal/auth"
	"github.com/Chappydev/Chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
  fileserverHits atomic.Int32
  queries *database.Queries
  platform string
  secret string
  polkaKey string
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
    UserID string `json:"user_id"`
  }

  token, err := auth.GetBearerToken(r.Header)
  if err != nil {
    w.WriteHeader(http.StatusUnauthorized)
    return
  }

  userID, err := auth.ValidateJWT(token, cfg.secret)
  if err != nil {
    w.WriteHeader(http.StatusUnauthorized)
    return
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
  savedChirp, err := cfg.queries.CreateChirp(r.Context(), database.CreateChirpParams{Body: cleanedBody, UserID: userID})
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
  authorIDString := r.URL.Query().Get("author_id")
  authorID, err := uuid.Parse(authorIDString)

  var allChirps []database.Chirp

  if len(authorID) == 0 {
    allChirps, err = cfg.queries.GetAllChirps(r.Context())
    if err != nil {
      w.WriteHeader(http.StatusInternalServerError)
      log.Printf("[GET /api/chirps] Fail to fetch chirps: %v\n", err)
      return
    }
  } else {
    allChirps, err = cfg.queries.GetAllChirpsFromUser(r.Context(), authorID) 
    if err != nil {
      w.WriteHeader(http.StatusInternalServerError)
      log.Printf("[GET /api/chirps] Fail to fetch chirps: %v\n", err)
      return
    }
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

func (cfg *apiConfig) handleDeleteChirp(w http.ResponseWriter, r *http.Request) {
  // Authenticate user
  token, err := auth.GetBearerToken(r.Header)
  if err != nil {
    w.WriteHeader(http.StatusUnauthorized)
    return
  }

  userID, err := auth.ValidateJWT(token, cfg.secret)
  if err != nil {
    w.WriteHeader(http.StatusUnauthorized)
    return
  }

  // get chirpID
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

  // Confirm user is authorized to delete the chirp
  _, err = cfg.queries.FindChirpByIDAndUserID(r.Context(), database.FindChirpByIDAndUserIDParams{
    ID: chirpID,
    UserID: userID,
  })
  if errors.Is(err, sql.ErrNoRows) {
    w.WriteHeader(http.StatusForbidden)
    return
  } else if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    return
  }

  err = cfg.queries.DeleteChirpByID(r.Context(), chirpID)
  if errors.Is(err, sql.ErrNoRows) {
    w.WriteHeader(http.StatusNotFound)
    return
  } else if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    return
  }

  w.WriteHeader(http.StatusNoContent)
}


func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {
  type bodyData struct {
    Email            string `json:"email"`
    Password         string `json:"password"`
  }

  type responseBodyStruct struct {
    ID           uuid.UUID `json:"id"`
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
    Email        string    `json:"email"`
    Token        string    `json:"token"`
    RefreshToken string    `json:"refresh_token"`
    IsChirpyRed  bool      `json:"is_chirpy_red"`
  }

  tokenExpireIn := time.Hour
  refreshExpiresIn := time.Hour * 24 * 60

  decoder := json.NewDecoder(r.Body)
  data := bodyData{}
  if err := decoder.Decode(&data); err != nil {
    w.WriteHeader(http.StatusBadRequest)
    resBody, err := json.Marshal(errorBody{Error: "Malformed body (must have email and password fields)"})
    if err == nil {
      w.Write(resBody)
    }
    return
  }

  user, err := cfg.queries.GetUserWithPasswordByEmail(r.Context(), data.Email)
  if err != nil {
    w.WriteHeader(http.StatusUnauthorized)
    resBody, err := json.Marshal(errorBody{Error: "incorrect email or password"})
    if err == nil {
      w.Write(resBody)
    }
    return
  }

  passwordMatches, _ := auth.CheckPasswordHash(data.Password, user.HashedPassword)
  if !passwordMatches {
    w.WriteHeader(http.StatusUnauthorized)
    resBody, err := json.Marshal(errorBody{Error: "incorrect email or password"})
    if err == nil {
      w.Write(resBody)
    }
    return
  }

  // Make refresh token 
  refreshToken, err := auth.MakeRefreshToken()
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    log.Printf("failed to make a refresh token: %v\n", err)
    return
  }
  refreshTokenData, err := cfg.queries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
    Token: refreshToken,
    UserID: user.ID,
    ExpiresAt: time.Now().Add(refreshExpiresIn),
  })
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    log.Printf("failed to save refresh token: %v\n", err)
    return
  }

  // Make JWT
  token, err := auth.MakeJWT(user.ID, cfg.secret, tokenExpireIn)
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    log.Printf("failed to make jwt: %v\n", err)
    return
  }

  // Return the user minus the password in the response body
  resBodyStruct := responseBodyStruct{
    ID: user.ID, 
    Email: user.Email, 
    CreatedAt: user.CreatedAt, 
    UpdatedAt: user.UpdatedAt, 
    Token: token,
    RefreshToken: refreshTokenData.Token,
    IsChirpyRed: user.IsChirpyRed,
  }
  resBody, err := json.Marshal(resBodyStruct)
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    log.Print("[POST /api/login] Failed to marshal noPassUser")
  }
  w.WriteHeader(http.StatusOK)
  w.Write(resBody)

}

func (cfg *apiConfig) handleRefresh(w http.ResponseWriter, r *http.Request) {
  type responseBodyStruct struct {
    Token string `json:"token"`
  }

  refreshToken, err := auth.GetBearerToken(r.Header)
  if err != nil {
    w.WriteHeader(http.StatusUnauthorized)
    return
  }

  // Check database to see if the token from the header exists and is valid
  token, err := cfg.queries.FindRefreshToken(r.Context(), refreshToken)
  if errors.Is(err, sql.ErrNoRows) || token.RevokedAt.Valid || time.Now().After(token.ExpiresAt) {
    // If there is no such token, or the token is invalid:
    w.WriteHeader(http.StatusUnauthorized)
    return
  } else if err == nil {
    // If we find the token and it is valid we make a new access token and send it

    accessToken, err := auth.MakeJWT(token.UserID, cfg.secret, time.Hour)
    if err != nil {
      w.WriteHeader(http.StatusInternalServerError)
      log.Printf("[POST /api/refresh] failed to make JWT: %v\n", err)
      return
    }

    w.WriteHeader(http.StatusOK)
    resBodyStruct := responseBodyStruct{Token: accessToken}
    resBody, err := json.Marshal(resBodyStruct)
    if err == nil {
      w.Write(resBody)
    }
    return
  } 

  // We don't know what went wrong so Internal Error 
  w.WriteHeader(http.StatusInternalServerError)
  log.Printf("[POST /api/refresh] failed to fetch refreshToken: %v\n", err)
}

func (cfg *apiConfig) handleRevoke(w http.ResponseWriter, r *http.Request) {
  refreshToken, err := auth.GetBearerToken(r.Header)
  if err != nil {
    w.WriteHeader(http.StatusUnauthorized)
    return
  }

  err = cfg.queries.RevokeToken(r.Context(), refreshToken)
  if errors.Is(err, sql.ErrNoRows) {
    w.WriteHeader(http.StatusUnauthorized)
    return
  } else if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    return
  }

  // Successful with no content
  w.WriteHeader(http.StatusNoContent)
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
    Password string `json:"password"`
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

  // Hash the password
  hashedPassword, err := auth.HashPassword(userParams.Password)
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    log.Printf("[POST /api/users] Failed to hash password: %v\n", err)
  }

  user, err := cfg.queries.CreateUser(r.Context(), database.CreateUserParams{Email: userParams.Email, HashedPassword: hashedPassword})
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

func (cfg *apiConfig) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
  type requestBody struct {
    Password string `json:"password"`
    Email string `json:"email"`
  }

  token, err := auth.GetBearerToken(r.Header)
  if err != nil {
    w.WriteHeader(http.StatusUnauthorized)
    return
  }

  userID, err := auth.ValidateJWT(token, cfg.secret)
  if err != nil {
    w.WriteHeader(http.StatusUnauthorized)
    return
  }

  decoder := json.NewDecoder(r.Body)
  var reqBody requestBody
  if err := decoder.Decode(&reqBody); err != nil {
    w.WriteHeader(400)
    w.Write([]byte("{\"error\": \"failed to parse request body as json\"}"))
    return
  }

  hashedPassword, err := auth.HashPassword(reqBody.Password)
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    log.Printf("[PUT /api/users] failed to hash password: %v\n", err)
  }

  updatedUser, err := cfg.queries.UpdateUserEmailAndPassword(r.Context(), database.UpdateUserEmailAndPasswordParams{
    Email: reqBody.Email,
    HashedPassword: hashedPassword,
    ID: userID,
  })
  if errors.Is(err, sql.ErrNoRows) {
    w.WriteHeader(http.StatusUnauthorized)
    return
  } else if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    log.Printf("[PUT /api/users] failed to update user: %v\n", err)
    return
  }
  resBody, err := json.Marshal(updatedUser)
  if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    log.Printf("[PUT /api/users] failed to marshal json body: %v\n", err)
    return
  }

  w.WriteHeader(http.StatusOK)
  w.Write(resBody)
}

func (cfg *apiConfig) handleWebhooks(w http.ResponseWriter, r *http.Request) {
  type requestBody struct {
    Event string `json:"event"`
    Data struct{
      UserID string `json:"user_id"`
    } `json:"data"`
  }

  expectedAPIKey := cfg.polkaKey
  apiKey, err := auth.GetAPIKey(r.Header)
  if err != nil || expectedAPIKey != apiKey {
    w.WriteHeader(http.StatusUnauthorized)
    return
  }

  decoder := json.NewDecoder(r.Body)
  reqBody := requestBody{}
  if err := decoder.Decode(&reqBody); err != nil {
    w.WriteHeader(http.StatusBadRequest)
    return
  }

  if reqBody.Event != "user.upgraded" {
    w.WriteHeader(http.StatusNoContent)
    return
  }

  id, err := uuid.Parse(reqBody.Data.UserID)
  if err != nil {
    w.WriteHeader(http.StatusBadRequest)
    return
  }

  // Upgrade the user
  err = cfg.queries.SetUserToRedByID(r.Context(), id)
  if errors.Is(err, sql.ErrNoRows) {
    w.WriteHeader(http.StatusNotFound)
    return
  } else if err != nil {
    w.WriteHeader(http.StatusInternalServerError)
    return
  }

  w.WriteHeader(http.StatusNoContent)
}

func main() {
  port := "8080"

  apiCfg := &apiConfig{}
  mux := http.NewServeMux()

  godotenv.Load()
  
  apiCfg.secret = os.Getenv("JWT_SECRET")
  apiCfg.platform = os.Getenv("PLATFORM")
  apiCfg.polkaKey = os.Getenv("POLKA_KEY")

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
  mux.HandleFunc("PUT /api/users", apiCfg.handleUpdateUser)
  mux.HandleFunc("GET /api/chirps", apiCfg.handleGetAllChirps)
  mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handleChirpByID)
  mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handleDeleteChirp)
  mux.HandleFunc("POST /api/login", apiCfg.handleLogin)
  mux.HandleFunc("POST /api/refresh", apiCfg.handleRefresh)
  mux.HandleFunc("POST /api/revoke", apiCfg.handleRevoke)
  mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handleWebhooks)

  // Server config
  server := &http.Server{
    Addr: ":" + port, 
    Handler: mux,
  }

  log.Printf("Server running on port %s\n", port)
  log.Fatal(server.ListenAndServe())
}
