package api

import (
	"log"
	"net/http"
)

type Server struct {
	Handler http.Handler
}

func (s *Server) Start(addr string) {
	log.Println("API running on", addr)
	log.Fatal(http.ListenAndServe(addr, s.Handler))
}
