package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/webteleport/wtf"
)

type Response struct {
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	ProxyConfig *ProxyConfig  `json:"proxyConfig"`
}

func getEnvMap() map[string]string {
	envMap := make(map[string]string)
	for _, e := range os.Environ() {
		// split "key=value"
		for i := 0; i < len(e); i++ {
			if e[i] == '=' {
				envMap[e[:i]] = e[i+1:]
				break
			}
		}
	}
	return envMap
}

func handlerFunc(proxyCfg *ProxyConfig) http.Handler {
	handler := func (w http.ResponseWriter, r *http.Request) {
		resp := Response{
			Args: os.Args,
			Env:  getEnvMap(),
			ProxyConfig: proxyCfg,
		}
		
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
	return http.HandlerFunc(handler)
}
	
func Sidecar(proxyCfg *ProxyConfig) {
	addr := "https://ufo.k0s.io/naive?persist=1"
	log.Println("Listening on", addr)
	wtf.Serve(addr, handlerFunc(proxyCfg))
}
