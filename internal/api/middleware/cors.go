package middleware

import "net/http"

// CORS allows browser-based clients (web dev, extension, Capacitor WebView)
// to reach the API from a different origin.
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if origin != "" && isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "3600")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func isAllowedOrigin(origin string) bool {
	switch origin {
	case "http://localhost:5173",
		"http://localhost:5174",
		"https://localhost",
		"capacitor://localhost":
		return true
	}

	// Production web frontend
	const pagesSuffix = ".pages.dev"
	if len(origin) > len(pagesSuffix) && origin[len(origin)-len(pagesSuffix):] == pagesSuffix {
		return true
	}

	// chrome-extension://<id>
	const chromeExt = "chrome-extension://"
	if len(origin) > len(chromeExt) && origin[:len(chromeExt)] == chromeExt {
		return true
	}

	// *.trycloudflare.com (dev tunnel)
	const cfSuffix = ".trycloudflare.com"
	if len(origin) > len(cfSuffix) && origin[len(origin)-len(cfSuffix):] == cfSuffix {
		return true
	}

	return false
}
