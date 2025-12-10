# Nom du binaire
BINARY_NAME=argos
# Dossier d'installation système
INSTALL_DIR=/usr/local/bin

# 1. Commande par défaut (Build seulement)
all: build

# 2. Compilation
build:
	@echo "Construction de $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) main.go
	@echo "✅ Build terminé."

# 3. Installation (Nécessite sudo)
install: build
	@echo "Installation dans $(INSTALL_DIR)..."
	sudo mv $(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	sudo chmod +x $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "✅ Installation terminée ! Tapez '$(BINARY_NAME)' pour lancer."

# 4. Désinstallation
uninstall:
	@echo "Suppression de $(BINARY_NAME)..."
	sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "✅ Désinstallé."

# 5. Nettoyage des fichiers locaux
clean:
	@echo "Nettoyage..."
	rm -f $(BINARY_NAME)
	@echo "✅ Propre."