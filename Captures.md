**Sécurité des systèmes d'exploitation et des réseaux**

# Travail pratique n° 3 — Annexe
## Guide d'acquisition des captures d'écran

| | |
|---|---|
| **Système cible** | Metasploitable 2 (Ubuntu 8.04 LTS) |
| **Document** | Annexe — preuves visuelles |
| **Auteur** | Raian Remir |
| **Date** | Juin 2026 |
| **Version** | 1.0 |

---


Ce dossier rassemble les captures d'écran qui servent de preuves visuelles au
rapport. Pour chaque capture, la commande à exécuter et l'élément à mettre en
évidence sont indiqués. Nommer les fichiers selon la colonne « Fichier » facilite
leur association avec les thèmes du plan de durcissement.

## Analyse (état initial)

| Fichier | Commande | À montrer |
|---|---|---|
| `00_analyse_ports_avant.png` | `sudo netstat -tulpn` | Les ~25 ports exposés au départ (dont les backdoors) |
| `00_analyse_nmap.png` | `nmap -sV 192.168.58.128` (depuis le poste) | Les services et versions détectés |

## Thème 1 — Neutralisation des backdoors

| Fichier | Commande | À montrer |
|---|---|---|
| `01_backdoors_avant.png` | `sudo netstat -tulpn \| grep -E ':21 \|:1099\|:1524\|:5900\|:6667\|:8787'` | Les backdoors actives — AVANT |
| `01_backdoors_apres.png` | la même commande après neutralisation | Aucune ligne (backdoors neutralisées) |
| `01_ingreslock_test.png` | `Test-NetConnection 192.168.58.128 -Port 1524` (poste) | `TcpTestSucceeded : False` |

## Thème 2 — Services inutiles

| Fichier | Commande | À montrer |
|---|---|---|
| `02_services_apres.png` | `sudo netstat -tulpn` | Seuls 22, 80, 3306 subsistent |

## Thème 3 — MySQL en écoute locale

| Fichier | Commande | À montrer |
|---|---|---|
| `03_mysql_avant.png` | `sudo netstat -tulpn \| grep 3306` | `0.0.0.0:3306` — AVANT |
| `03_mysql_apres.png` | la même commande + `Test-NetConnection ... -Port 3306` | `127.0.0.1:3306` + test distant False |

## Thème 4 — SSH

| Fichier | Commande | À montrer |
|---|---|---|
| `04_ssh_config.png` | `sudo grep -nE '^(Protocol\|PermitRootLogin\|PasswordAuthentication\|PubkeyAuthentication)' /etc/ssh/sshd_config` | root interdit, mot de passe off, clé activée |
| `04_ssh_test.png` | depuis le poste : `ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no msf` | `Permission denied (publickey)` |

## Thème 5 — Pare-feu

| Fichier | Commande | À montrer |
|---|---|---|
| `05_iptables.png` | `sudo iptables -L -n -v` | Politique DROP, seuls 80 et 22 (LAN) autorisés |

## Thème 6 — Moindre privilège

| Fichier | Commande | À montrer |
|---|---|---|
| `06_comptes.png` | `sudo grep -vE '^#\|^$' /etc/sudoers` + `passwd -S user service postgres` | sudoers limité, comptes faibles verrouillés |

## Thème 7 — Apache et MySQL durcis

| Fichier | Commande | À montrer |
|---|---|---|
| `07_apache_banner.png` | `curl -I http://localhost/ \| grep -i server` | `Server: Apache` (version masquée) |
| `07_mysql_users.png` | `mysql -u root -p<MDP> -e "SELECT User,Host FROM mysql.user;"` | Comptes dédiés localhost, plus de root@'%' ni guest |

## Thème 8 — Système de fichiers

| Fichier | Commande | À montrer |
|---|---|---|
| `08_tmp_shadow.png` | `mount \| grep /tmp` + `ls -l /etc/shadow` | /tmp en noexec,nosuid,nodev et shadow en 600 |

## Validation finale

| Fichier | Commande | À montrer |
|---|---|---|
| `99_validation_finale.png` | bloc complet de la section « Validation finale » du plan | 3 services exposés, DROP, MySQL local, DVWA en 200 |

---

Astuce : la capture `99_validation_finale.png` à elle seule résume l'aboutissement du
durcissement (surface réduite + MySQL local + applications fonctionnelles) ; c'est la
plus convaincante à placer en conclusion.
