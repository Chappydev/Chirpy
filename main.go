package main

import "net/http"

func main() {
  port := "8080"

  mux := http.NewServeMux()
  
  // Handlers
  mux.Handle("/", http.FileServer(http.Dir(".")))

  server := &http.Server{
    Addr: ":" + port, 
    Handler: mux,
  }

  server.ListenAndServe()
}
