# TP3 — Durcissement d'un serveur Linux (Metasploitable 2)

Analyse de la surface d'attaque et durcissement d'une machine Metasploitable 2
(Ubuntu 8.04) hébergeant deux applications web volontairement vulnérables, DVWA et
Mutillidae, qui doivent rester fonctionnelles.

La machine étant délibérément vulnérable et hébergeant des backdoors actives, elle
ne doit être utilisée que sur un réseau isolé (Host-only ou NAT). Les mots de passe
de ce dépôt sont des placeholders. L'objectif n'est pas de corriger l'ensemble des
vulnérabilités, ce qui n'est ni possible (système en fin de vie, applications
vulnérables par conception) ni demandé, mais de réduire la surface d'attaque et de
durcir le système en cohérence avec son rôle.

## Contexte technique

Ubuntu 8.04 fonctionne avec SysVinit, xinetd et inetd (service, update-rc.d,
/etc/xinetd.d, /etc/inetd.conf). Le pare-feu repose sur iptables, le noyau étant
antérieur à nftables. L'énumération s'effectue avec netstat et ifconfig. Les dépôts
APT étant fermés, les composants ne sont pas corrigeables ; la migration vers un
système supporté constitue la correction de fond.

## Structure du dépôt

| Fichier | Description |
|---|---|
| [01_analyse.md](01_analyse.md) | Cartographie du système et analyse de la surface d'attaque |
| [02_plan_durcissement.md](02_plan_durcissement.md) | Plan de durcissement (état initial, mesures, vérification, état final) |
| [diagrams/](diagrams/) | Sources Mermaid des schémas |

## Mesures appliquées

| Thème | Mesure | Impact métier |
|---|---|---|
| 1 | Neutralisation des backdoors (ingreslock, UnrealIRCd, RMI, DRb, vsftpd) | aucun |
| 2 | Suppression des services inutiles (Samba, NFS, BIND, PostgreSQL, Tomcat, distccd, ProFTPD, Postfix) | aucun |
| 3 | MySQL restreint à l'écoute locale (127.0.0.1) | aucun |
| 4 | SSH par clé, root interdit, SSHv2 | administration par clé |
| 5 | Pare-feu iptables, politique DROP (80 et 22 restreint) | aucun |
| 6 | Mot de passe par défaut changé, comptes faibles verrouillés | aucun |
| 7 | Apache et MySQL durcis, comptes applicatifs dédiés | applications préservées |
| 8 | /tmp durci, droits sensibles restreints | aucun |

La surface d'attaque passe d'environ vingt-cinq services exposés, dont cinq
backdoors root, à trois services nécessaires durcis, DVWA et Mutillidae restant
fonctionnelles.

## Schémas

Les sources éditables sont dans le dossier [diagrams/](diagrams/).

### Services necessaires, inutiles et backdoors

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

### Ports exposes avant et apres durcissement

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

### Flux d'une requete apres durcissement

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

## Auteur

Raian Remir — TP3 Sécurité des OS et des réseaux

