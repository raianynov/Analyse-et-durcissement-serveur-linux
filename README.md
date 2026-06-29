---
**Sécurité des systèmes d'exploitation et des réseaux**

# Travail pratique n° 3
## Analyse et durcissement d'un serveur Linux

| | |
|---|---|
| **Système cible** | Metasploitable 2 (Ubuntu 8.04 LTS) |
| **Document** | Note de synthèse |
| **Auteur** | Prénom NOM |
| **Date** | Juin 2026 |
| **Version** | 1.0 |
| **Diffusion** | Usage pédagogique — réseau isolé |

---

## 1. Objet du document

Ce dossier présente l'analyse de la surface d'attaque et le durcissement d'une
machine **Metasploitable 2** (Ubuntu 8.04 LTS) hébergeant deux applications web
délibérément vulnérables, DVWA et Mutillidae, qui doivent demeurer fonctionnelles.

La machine étant volontairement vulnérable et hébergeant des portes dérobées
actives, son utilisation est strictement réservée à un réseau isolé (hôte seul ou
NAT). Les mots de passe figurant dans ce dossier sont des valeurs de remplacement.
L'objectif n'est pas de corriger l'ensemble des vulnérabilités — ce qui n'est ni
réalisable (système en fin de vie, applications vulnérables par conception) ni
demandé — mais de réduire la surface d'attaque et de durcir le système en cohérence
avec son rôle.

## 2. Contexte technique

Ubuntu 8.04 repose sur SysVinit, complété par xinetd et inetd (commandes `service`,
`update-rc.d`, fichiers `/etc/xinetd.d`, `/etc/inetd.conf`). Le pare-feu repose sur
iptables, le noyau étant antérieur à nftables. L'énumération s'effectue avec
`netstat` et `ifconfig`. Les dépôts APT étant fermés, les composants ne sont pas
corrigeables ; la migration vers un système supporté constitue la correction de
fond.

## 3. Composition du dossier

| Élément | Description |
|---|---|
| `01_analyse.md` | Cartographie du système et analyse de la surface d'attaque |
| `02_plan_durcissement.md` | Plan de durcissement (état initial, mesures, vérification, état final) |
| `diagrams/` | Sources des schémas au format Mermaid |
| `captures/` | Captures d'écran (preuves visuelles) et guide d'acquisition |

## 4. Synthèse des mesures appliquées

| N° | Mesure | Incidence sur le service |
|---|---|---|
| 1 | Neutralisation des portes dérobées (ingreslock, UnrealIRCd, Java RMI, Ruby DRb, vsftpd) | Aucune |
| 2 | Suppression des services superflus (Samba, NFS, BIND, PostgreSQL, Tomcat, distcc, ProFTPD, Postfix) | Aucune |
| 3 | Restriction de MySQL à l'écoute locale (127.0.0.1) | Aucune |
| 4 | Authentification SSH par clé, interdiction du superutilisateur, SSHv2 imposé | Administration par clé |
| 5 | Pare-feu iptables, politique de rejet par défaut (80 ouvert, 22 restreint) | Aucune |
| 6 | Changement du mot de passe par défaut, verrouillage des comptes faibles | Aucune |
| 7 | Durcissement d'Apache et de MySQL, comptes applicatifs dédiés | Applications préservées |
| 8 | Durcissement de /tmp, restriction des droits sensibles | Aucune |

La surface d'attaque passe d'environ vingt-cinq services exposés — dont cinq portes
dérobées donnant un accès *root* — à trois services nécessaires et durcis, DVWA et
Mutillidae demeurant fonctionnelles.

## 5. Schémas

Les sources éditables figurent dans le dossier `diagrams/`.

### 5.1 Services nécessaires, superflus et portes dérobées

```mermaid
flowchart TB
    classDef keep fill:#cfe8cf,stroke:#2e7d32,color:#1b3a1b;
    classDef drop fill:#f3d2d2,stroke:#b71c1c,color:#3a0000;
    classDef back fill:#7a1f1f,stroke:#3a0000,color:#ffffff;

    subgraph NEED["Necessaires (conserver et durcir)"]
        S22["SSH 22 - administration"]:::keep
        S80["Apache/PHP 80 - DVWA + Mutillidae"]:::keep
        S3306["MySQL 3306 - a restreindre en 127.0.0.1"]:::keep
    end

    subgraph BACK["Backdoors (supprimer en priorite)"]
        ING["ingreslock 1524 - shell root"]:::back
        IRC["UnrealIRCd 6667/6697"]:::back
        RMI["Java RMI 1099"]:::back
        DRB["Ruby DRb 8787"]:::back
        VS["vsftpd 2.3.4 - port 21"]:::back
    end

    subgraph USELESS["Inutiles (desactiver / supprimer)"]
        TEL["Telnet 23 / r-services 512-514"]:::drop
        SMB["Samba 139/445/137/138"]:::drop
        NFS["NFS 2049 / portmap 111"]:::drop
        DNS["DNS 53 / SMTP 25 / TFTP 69"]:::drop
        PG["PostgreSQL 5432 / ProFTPD 2121"]:::drop
        JAVA["Tomcat 8009/8180 / distcc 3632 / VNC 5900 / X11 6000"]:::drop
    end
```

### 5.2 Ports exposés avant et après durcissement

```mermaid
flowchart LR
    classDef open fill:#f3d2d2,stroke:#b71c1c,color:#3a0000;
    classDef keep fill:#cfe8cf,stroke:#2e7d32,color:#1b3a1b;
    classDef local fill:#f3ead2,stroke:#8a6d00,color:#3a2f00;
    classDef filt fill:#cfe0f3,stroke:#1565c0,color:#0d2a4a;

    NET(("Réseau")):::filt

    subgraph BEFORE["AVANT — ~25 ports (dont 5 backdoors)"]
        BA["21 22 23 25 53 69 80 111 139 445
        512 513 514 1099 1524 2049 2121
        3306 3632 5432 5900 6000 6667
        6697 8009 8180 8787 ..."]:::open
    end

    subgraph AFTER["APRÈS — surface minimale"]
        A80["80/tcp Apache — ouvert (métier)"]:::keep
        A22["22/tcp SSH — filtré (192.168.58.0/24)"]:::filt
        A3306["3306/tcp MySQL — 127.0.0.1 uniquement"]:::local
        AX["tous les autres ports — fermés / DROP"]:::keep
    end

    NET --> BEFORE
    NET -->|"iptables : politique DROP"| AFTER
```

### 5.3 Flux d'une requête après durcissement

```mermaid
sequenceDiagram
    autonumber
    participant C as Client / Admin
    participant FW as iptables (policy DROP)
    participant A as Apache + PHP (80)
    participant APP as DVWA / Mutillidae
    participant DB as MySQL (127.0.0.1:3306)

    C->>FW: HTTP vers 80  /  SSH vers 22
    Note over FW: Autorisés : 80 (tous),<br/>22 (192.168.58.0/24), established, lo<br/>Tout le reste : DROP
    FW->>A: Requête HTTP autorisée (80)
    A->>APP: Exécution du code PHP
    APP->>DB: Requête SQL en local (comptes dédiés dvwa / mutillidae)
    DB-->>APP: Résultats
    APP-->>A: Page HTML
    A-->>C: Réponse HTTP
    Note over DB: MySQL non exposé au réseau<br/>(écoute 127.0.0.1 uniquement)
```

## 6. Périmètre et limites

Metasploitable 2 repose sur Ubuntu 8.04, en fin de vie : les dépôts APT sont fermés
et les composants (Apache, PHP, MySQL) ne sont pas corrigeables. La suppression de
l'ensemble des vulnérabilités n'est pas l'objet de ce travail — les applications
devant rester vulnérables et fonctionnelles — et n'est de toute façon pas atteignable
sur cette base. La correction de fond des versions relève d'une migration vers un
système supporté, qui constitue la recommandation principale.

---
*Document rédigé dans le cadre du module Sécurité des systèmes d'exploitation et des
réseaux.*
