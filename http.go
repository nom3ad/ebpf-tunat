package main

import (
	"encoding/json"
	"net/http"
)

type APIService struct {
	http.ServeMux
	registry *ServiceRegistry
}

func NewAPIService(registry *ServiceRegistry) *APIService {
	as := &APIService{
		registry: registry,
	}
	as.HandleFunc("/services", as.handleServices)
	return as
}

func (as *APIService) handleServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(as.registry.services)
}
