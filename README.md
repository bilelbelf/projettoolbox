# 📑📝 Security Toolbox 📄👨‍💻

Security Toolbox est une application de sécurité développée en Python, permettant d'effectuer différentes analyses de sécurité telles que l'analyse de mot de passe, l'analyse de port, les tests de brute force SSH, et le scan de vulnérabilités. Cette application utilise des bibliothèques et des outils populaires tels que nmap, paramiko, tkinter, zxcvbn, FPDF, et vulners.

# Fonctionnalités 👨‍💻

### Authentification Utilisateur

Interface de connexion sécurisée avec validation des identifiants.

### Analyse de Mot de Passe

- Vérification de la force du mot de passe.
- Suggestions d'amélioration.
- Détection de réutilisation de mot de passe due à un système de hashage.

### Analyse de Port

- Scan des ports ouverts sur une adresse IP.
- Détails sur les services et versions des services trouvés.

### Test Bruteforce SSH

- Tentative de connexion SSH avec une liste de mots de passe courants.
- Génération de combinaisons de mots de passe basées sur les informations renseignées par l'utilisateur visant la victime.

### Scan de Vulnérabilité

- Recherche de vulnérabilités connues sur les services trouvés via l'API Vulners.
- Scan de port via NMAP.
- Affichage des résultats avec détails sur les CVE et les scores CVSS.

# Prérequis 📝

- ### Python 3.6 ou supérieur
- ### IDE (exemple : VScode)
  ![1](https://raw.githubusercontent.com/SP-XD/SP-XD/main/images/dev-working_rounded.gif)

# Installation ☑️

### Bibliothèques Python :

1. `nmap` : **Utilisation** : Utilisé pour scanner les réseaux. Interface Python pour Nmap.
   - **Installation** : `pip install python-nmap`
   
2. `paramiko` : **Utilisation** : Fournit des outils pour les connexions SSH et SCP en Python.
   - **Installation** : `pip install paramiko`

3. `numpy` : **Utilisation** : Bibliothèque pour le calcul numérique avec des tableaux multidimensionnels.
   - **Installation** : `pip install numpy`

4. `zxcvbn` : **Utilisation** : Bibliothèque pour estimer la force des mots de passe.
   - **Installation** : `pip install zxcvbn`

5. `fpdf` : **Utilisation**: Génération de fichiers PDF en Python.
   - **Installation** : `pip install fpdf`

6. `docx` : **Utilisation**: Manipulation de documents Word (.docx) en Python.
   - **Installation** : `pip install python-docx`

7. `vulners` : **Utilisation** Interface avec la base de données de vulnérabilités Vulners pour la recherche de vulnérabilités.
   - **Installation** : `pip install vulners`

### Fichiers nécessaires :

- **Pour le scan de vulnérabilité** : `vuln_api` Fichier contenant la clé API pour accéder à l'API Vulners. Inscrivez-vous sur [Vulners](https://vulners.com/) pour obtenir une clé API.
- **Pour l'analyse de mot de passe** : `probable-v2-top12000.txt` Fichier contenant une liste de mots de passe communs pour effectuer les tests de brute force.
- `resultat.txt` : Fichier où les mots de passe hachés sont enregistrés pour vérifier leur réutilisation. Ce fichier est généré automatiquement par le script si absent.
- **Nmap doit être installé et ajouté au PATH ([https://nmap.org/book/inst-windows.html](https://nmap.org/book/inst-windows.html))**

# Utilisation 👨‍💻

## Authentification
Exécutez le script principal. Une fenêtre d'authentification apparaîtra. Utilisez les identifiants `admin/admin` pour vous connecter.

## Interface Principale
Après authentification, vous accéderez à la fenêtre principale où vous pouvez choisir parmi les différentes analyses proposées.

## Analyses et Scans
- **Analyse de Mot de Passe** : Entrez un mot de passe pour analyser sa robustesse, sa sécurité (de 1 à 4) et si il a deja été utilisé auparavant ou non.
- **Analyse de Port** : Entrez une IP pour scanner les ports ouverts, les services associés et leurs versions.
- **Test Bruteforce SSH** : Entrez une IP, nom d'utilisateur, prénom de la victime (facultatif), date de naissance de la victime (facultatif) pour effectuer un test de brute force.
- **Scan de Vulnérabilité** : Entrez une IP et une plage de ports pour vérifier les vulnérabilités des services détectés avec le lien de la CVE si possible.

## Génération de Rapports
Les résultats des scans et analyses peuvent être exportés sous forme de fichiers PDF ou DOCX. Une option de génération de rapport est disponible après chaque scan/analyse.

## Conclusion et Perspectives
Cette boîte à outils a été développée pour simplifier et améliorer les tests de sécurité. Nous continuons à améliorer ses fonctionnalités et à ajouter de nouvelles capacités pour répondre aux besoins en constante évolution du domaine de la cybersécurité.

Pour toute question ou suggestion, n'hésitez pas à nous contacter par mail : bilelbelferroum.pro@gmail.com.

Suivez les instructions à l'écran pour naviguer dans les différentes fonctionnalités de l'application.

# Structure du Projet 📝
- `main.py` : Fichier principal pour lancer l'application.
- `LoginWindow` : Gère l'authentification de l'utilisateur.
- `MainWindow` : Interface principale de l'application avec différentes options de sécurité.
- `CVEcheck` : Classe pour la vérification des vulnérabilités.
- `scan_vulns` : Fonction pour scanner les vulnérabilités avec nmap.
- `generate_password_combinations` : Fonction pour générer des combinaisons de mots de passe.
- `save_report` : Fonction pour sauvegarder les rapports en PDF ou DOCX.

# Exemples d'Utilisation 👨‍💻

### Analyse de Mot de Passe
1. Lancez l'analyse via l'interface.
2. Entrez le mot de passe à analyser.
3. Visualisez les résultats et générez un rapport.

### Scan de Vulnérabilité
1. Lancez le scan via l'interface.
2. Entrez l'IP cible et la plage de ports.
3. Visualisez les vulnérabilités trouvées et générez un rapport.

# Auteurs
- Bilel BELFERROUM (bilelbelferroum.pro@gmail.com)
