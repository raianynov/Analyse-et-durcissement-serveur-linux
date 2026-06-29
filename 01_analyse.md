**Sécurité des systèmes d'exploitation et des réseaux**

# Travail pratique n° 3
## Analyse et durcissement d'un serveur Linux

| | |
|---|---|
| **Système cible** | Metasploitable 2 (Ubuntu 8.04 LTS) |
| **Document** | Partie 1 — Analyse du système |
| **Auteur** | Raian Remir |
| **Date** | Juin 2026 |
| **Version** | 1.0 |
| **Diffusion** | Usage pédagogique — réseau isolé |

---

## Sommaire

1. Fonction métier
2. Identification du système
3. Cartographie des ports et services
4. Dépendances applicatives
5. Analyse de la surface d'attaque
6. Périmètre et limites

---

## 1. Fonction métier

La machine Metasploitable 2 (Ubuntu 8.04) héberge deux applications web vulnérables
à vocation pédagogique, DVWA et Mutillidae, servies par Apache et adossées à une
base MySQL. La fonction du serveur se limite à servir ces applications (HTTP/PHP et
base de données) et à permettre son administration (SSH). Tout composant ne
contribuant pas à ce rôle constitue une surface d'attaque inutile.

## 2. Identification du système

| Élément | Valeur |
|---|---|
| Distribution | Ubuntu 8.04 LTS (Hardy Heron) |
| Noyau | Linux 2.6.x |
| Système d'init | SysVinit, complété par xinetd et inetd |
| Serveur web | Apache 2.2.8 avec PHP 5.2 |
| Base de données | MySQL 5.0.51a |
| Accès distant | OpenSSH 4.7p1 |
| Adresse IP | 192.168.58.128/24 |
| Compte d'administration | msfadmin |

## 3. Cartographie des ports et services

Relevé obtenu par `sudo netstat -tulpn`. La colonne Rôle qualifie chaque composant
au regard de la fonction métier.

| Port | Service | Programme | Rôle |
|---|---|---|---|
| 21 | FTP | xinetd (vsftpd 2.3.4) | Backdoor (CVE-2011-2523) |
| 22 | SSH | sshd | Nécessaire |
| 23 | Telnet | xinetd | Inutile (protocole en clair) |
| 25 | SMTP | Postfix | Inutile |
| 53 | DNS | named (BIND 9) | Inutile |
| 69 | TFTP | xinetd | Inutile |
| 80 | HTTP | apache2 | Nécessaire |
| 111 | RPC portmapper | portmap | Inutile (dépendance NFS) |
| 139, 445 | SMB | smbd, nmbd | Inutile (CVE-2007-2447) |
| 512, 513, 514 | rexec, rlogin, rsh | xinetd | Inutile (auth faible, en clair) |
| 1099 | Java RMI | rmiregistry | Backdoor (exécution de code distante) |
| 1524 | ingreslock | xinetd | Backdoor (shell root sans authentification) |
| 2049 | NFS | nfsd | Inutile |
| 2121 | FTP | ProFTPD 1.3.1 | Inutile |
| 3306 | MySQL | mysqld | Nécessaire, à restreindre à l'écoute locale |
| 3632 | distcc | distccd | Backdoor (CVE-2004-2687) |
| 5432 | PostgreSQL | postgres | Inutile |
| 5900 | VNC | Xtightvnc | Backdoor (mot de passe faible) |
| 6000 | X11 | Xtightvnc | Inutile |
| 6667, 6697 | IRC | UnrealIRCd | Backdoor (CVE-2010-2075) |
| 8009, 8180 | AJP, HTTP | Tomcat | Inutile |
| 8787 | DRb | ruby | Backdoor (exécution de code distante) |

## 4. Dépendances de DVWA et Mutillidae

Les deux applications partagent la même pile technique.

```
Navigateur (HTTP/80)
   -> Apache 2.2.8 + PHP
      -> /var/www/dvwa, /var/www/mutillidae
         -> MySQL 5.0.51a (local)
```

Flux nécessaires au fonctionnement :

1. Entrant : client vers le port 80 (Apache). Seul flux entrant métier.
2. Interne : Apache et PHP vers MySQL, en local. La base n'a pas besoin d'être
   exposée au réseau ; elle écoute pourtant initialement sur 0.0.0.0:3306.
3. Administration : administrateur vers le port 22 (SSH), à restreindre à un
   réseau de confiance.

Composants à conserver : Apache (80), MySQL (à restreindre au local), SSH (22).

## 5. Analyse de la surface d'attaque

### 5.1 Éléments à protéger

Apache et PHP (port 80), unique porte d'entrée métier ; MySQL (port 3306), données
des applications, à restreindre à l'écoute locale ; SSH (port 22), canal
d'administration, à durcir.

### 5.2 Éléments à éliminer

| Famille | Services | Risque principal |
|---|---|---|
| Backdoors | ingreslock 1524, UnrealIRCd 6667/6697, FTP 21, distccd 3632, Java RMI 1099, DRb 8787 | Accès root direct, exécution de code distante |
| Protocoles en clair, auth faible | Telnet 23, rexec/rlogin/rsh 512-514, VNC 5900, TFTP 69 | Vol d'identifiants, interception |
| Partage réseau non requis | Samba 139/445/137/138, NFS 2049, portmap 111 | Accès fichiers, mouvement latéral |
| Hors périmètre | SMTP 25, DNS 53, PostgreSQL 5432, ProFTPD 2121, X11 6000, Tomcat 8009/8180 | Surface et vulnérabilités inutiles |

### 5.3 Synthèse

Sur environ vingt-cinq ports ouverts, trois services seulement sont nécessaires :
22, 80 et 3306 (à restreindre au local). Le durcissement consiste à neutraliser les
backdoors, supprimer les services inutiles, restreindre MySQL à l'écoute locale,
puis durcir SSH, le pare-feu, les privilèges et le système de fichiers, en
préservant le fonctionnement de DVWA et Mutillidae.

## 6. Périmètre et limites

Metasploitable 2 repose sur Ubuntu 8.04, en fin de vie : les dépôts APT sont fermés
et les composants (Apache, PHP, MySQL) ne sont pas corrigeables. La suppression de
l'ensemble des vulnérabilités n'est pas l'objet de ce travail, puisque DVWA et
Mutillidae doivent rester vulnérables et fonctionnelles, et n'est pas atteignable
sur cette base. La correction de fond des versions relève d'une migration vers un
système supporté, qui constitue la recommandation principale.
