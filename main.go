package main

import (
	"log"
	"net/http"
)

func main() {
  port := "8080"

  mux := http.NewServeMux()
  
  // Handlers
  mux.Handle("/app/", http.StripPrefix("/app", http.FileServer(http.Dir("."))))
  mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
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
