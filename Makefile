# ARGOS PANOPTES - Build System

# Nom du binaire
BINARY_NAME=argos
# Point d'entrée source
SOURCE_PATH=cmd/argos/main.go
# Dossier d'installation système
INSTALL_DIR=/usr/local/bin
# Flags d'optimisation (-s: désactive les symboles, -w: désactive DWARF)
LDFLAGS="-s -w"

# 1. Commande par défaut (Build)
all: build

# 2. Compilation Optimisée (Stripped)
build:
	@echo "[\033[36m*\033[0m] Forging $(BINARY_NAME) engine..."
	@go build -ldflags=$(LDFLAGS) -o $(BINARY_NAME) $(SOURCE_PATH)
	@echo "[\033[32m✓\033[0m] Build complete. Binary ready."

# 3. Compilation Multi-plateforme (Cross-Compilation)
build-all:
	@echo "[\033[36m*\033[0m] Cross-compiling for Linux/Windows/macOS..."
	GOOS=linux GOARCH=amd64 go build -ldflags=$(LDFLAGS) -o build/$(BINARY_NAME)_linux_amd64 $(SOURCE_PATH)
	GOOS=windows GOARCH=amd64 go build -ldflags=$(LDFLAGS) -o build/$(BINARY_NAME)_windows_amd64.exe $(SOURCE_PATH)
	GOOS=darwin GOARCH=arm64 go build -ldflags=$(LDFLAGS) -o build/$(BINARY_NAME)_macos_arm64 $(SOURCE_PATH)
	@echo "[\033[32m✓\033[0m] Binaries exported to build/ directory."

# 4. Installation Système (Nécessite sudo)
install: build
	@echo "[\033[36m*\033[0m] Deploying to $(INSTALL_DIR)..."
	sudo mv $(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	sudo chmod +x $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "[\033[32m✓\033[0m] System deployment successful! Type '$(BINARY_NAME)' to start."

# 5. Désinstallation
uninstall:
	@echo "[\033[36m*\033[0m] Removing $(BINARY_NAME) from system..."
	sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "[\033[32m✓\033[0m] Cleaned."

# 6. Nettoyage de l'espace de travail
clean:
	@echo "[\033[36m*\033[0m] Purging workspace..."
	@rm -f $(BINARY_NAME)
	@rm -rf build/
	@echo "[\033[32m✓\033[0m] Workspace pure."