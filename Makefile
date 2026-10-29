.PHONY: build frontend backend test dev clean

build: frontend backend

frontend:
	cd frontend && npm install && npm run build

backend:
	cd backend && go build -o ../blue-siem .

test:
	cd backend && go test ./...

# Backend on :8080; run `npm run dev` in frontend/ for hot reload (proxies /api).
dev:
	cd backend && go run . -db ../siem.db

clean:
	rm -f blue-siem blue-siem.exe
