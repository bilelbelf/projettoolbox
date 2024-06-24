# 📑📝 Security Toolbox 📄👨‍💻

Security Toolbox est une application de sécurité développée en Python, permettant d'effectuer différentes analyses de sécurité telles que l'analyse de mot de passe, l'analyse de port, les tests de brute force SSH, et le scan de vulnérabilités. Cette application utilise des bibliothèques et des outils populaires tels que nmap, paramiko, tkinter, zxcvbn, FPDF, et vulners.

# Fonctionnalités


### Authentification Utilisateur

Interface de connexion sécurisée avec validation des identifiants.

### Analyse de Mot de Passe

- Vérification de la force du mot de passe.
- Suggestions d'amélioration.
- Détection de réutilisation de mot de passe.

### Analyse de Port

- Scan des ports ouverts sur une adresse IP.
- Détails sur les services et versions des services trouvés.
- Test Bruteforce SSH

### Test Bruteforce SSH

- Tentative de connexion SSH avec une liste de mots de passe courants.
- Génération de combinaisons de mots de passe basées sur les informations renseignées par l'utilisateur visant la victime.


### Scan de Vulnérabilité

- Recherche de vulnérabilités connues sur les services trouvés via l'API Vulners.
- Scan de port via NMAP
- Affichage des résultats avec détails sur les CVE et les scores CVSS.
  
# Prérequis

- **Python 3.6 ou supérieur** 
- **Bibliothèques Python** :
````
1. os
2. tkinter
3.  threading
4.  nmap
5.  paramiko
6.  numpy
7.  socket
8.  hashlib
9.  zxcvbn
10.  fpdf
11.  docx
12.  time
13.  vulners
````
- Nmap doit être installé et ajouté au PATH (https://nmap.org/book/inst-windows.html)
Installation
Clonez le dépôt :
sh
Copier le code
git clone https://github.com/votre-utilisateur/votre-repo.git
cd votre-repo
Installez les dépendances :

sh
Copier le code
pip install -r requirements.txt
Assurez-vous que Nmap est installé et accessible via le PATH.

Créez un fichier vuln_api à la racine du projet et ajoutez votre clé API Vulners.

Utilisation
Lancez l'application avec la commande suivante :

sh
Copier le code
python main.py
Suivez les instructions à l'écran pour naviguer dans les différentes fonctionnalités de l'application.

Structure du Projet
main.py : Fichier principal pour lancer l'application.
LoginWindow : Gère l'authentification de l'utilisateur.
MainWindow : Interface principale de l'application avec différentes options de sécurité.
CVEcheck : Classe pour la vérification des vulnérabilités.
scan_vulns : Fonction pour scanner les vulnérabilités avec nmap.
generate_password_combinations : Fonction pour générer des combinaisons de mots de passe.
save_report : Fonction pour sauvegarder les rapports en PDF ou DOCX.
Exemples d'Utilisation
Analyse de Mot de Passe
Lancez l'analyse via l'interface.
Entrez le mot de passe à analyser.
Visualisez les résultats et générez un rapport.
Scan de Vulnérabilité
Lancez le scan via l'interface.
Entrez l'IP cible et la plage de ports.
Visualisez les vulnérabilités trouvées et générez un rapport.
Contributions
Les contributions sont les bienvenues ! Veuillez soumettre une pull request ou ouvrir une issue pour discuter des changements que vous souhaitez apporter.

Licence
Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

Auteurs
Votre Nom (votre-email@example.com)
