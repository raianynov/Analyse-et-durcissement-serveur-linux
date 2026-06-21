# Partie 1 — Analyse du système existant (Metasploitable 2)

## 1. Fonction métier du serveur

Machine **Metasploitable 2** (Ubuntu 8.04 « Hardy Heron ») hébergeant deux
applications web vulnérables à vocation pédagogique — **DVWA** et **Mutillidae** —
servies par Apache et adossées à une base **MySQL**. Sa fonction métier se limite à
**servir ces applications web (HTTP/PHP + base de données)** et à permettre son
**administration** (SSH).

Tout composant ne contribuant pas à ce rôle constitue une **surface d'attaque
inutile**. Metasploitable 2 étant délibérément vulnérable, elle expose en outre
plusieurs **portes dérobées (backdoors)** et services obsolètes.

## 2. Identification du système
| Élément | Valeur observée |
|---|---|
| Distribution | Ubuntu 8.04 LTS (Hardy Heron) |
| Noyau | Linux 2.6.x |
| Init | **SysVinit** (`/etc/init.d`, `/etc/rc*.d`) + **xinetd** + **inetd** |
| Gestion de paquets | APT / dpkg (dépôts fermés — non patchable) |
| Serveur web | Apache 2.2.8 + PHP |
| Base de données | MySQL 5.0.51a |
| Accès distant | OpenSSH 4.7p1 (n'accepte que `ssh-rsa`/`ssh-dss` — algorithmes obsolètes) |
| Adresse IP | 192.168.58.128/24 |
| Compte d'administration | `msfadmin` (mot de passe par défaut) |

## 3. Cartographie des ports et services

Relevé réel (`sudo netstat -tulpn`). Rôle vis-à-vis du métier :
✅ nécessaire · ⚠️ nécessaire mais à restreindre · ❌ inutile · ☠️ **backdoor**.

| Port(s) | Service | Programme | Rôle |
|---|---|---|---|
| 21 | FTP | xinetd | ❌ (FTP inutile ; versions Metasploitable connues vulnérables) |
| 22 | SSH | sshd | ✅ **Nécessaire** (administration) — à durcir |
| 23 | Telnet | xinetd | ❌ Protocole en clair |
| 25 | SMTP | Postfix (master) | ❌ Pas de rôle mail |
| 53 | DNS | named (BIND 9) | ❌ Pas de rôle DNS |
| 69/udp | TFTP | xinetd | ❌ Transfert sans authentification |
| 80 | HTTP | apache2 | ✅ **Nécessaire** (DVWA + Mutillidae) |
| 111 | RPC portmapper | portmap | ❌ Dépendance NFS |
| 139 / 445 | SMB | smbd / nmbd | ☠️ Samba 3.x (CVE-2007-2447, RCE « username map script ») |
| 137 / 138 udp | NetBIOS | nmbd | ❌ Inutile |
| 512 / 513 / 514 | rexec / rlogin / rsh | xinetd | ❌ r-services (auth faible, en clair) |
| 1099 / 39631 | Java RMI | rmiregistry | ☠️ RMI registry (exécution de code distante) |
| 1524 | ingreslock | xinetd | ☠️ **Backdoor shell root** |
| 2049 / 111 / mountd / statd | NFS / RPC | nfsd, rpc.mountd, rpc.statd | ❌ Partage réseau (souvent `no_root_squash`) |
| 2121 | FTP | ProFTPD 1.3.1 | ❌ Second service FTP |
| 3306 | MySQL | mysqld | ⚠️ **Nécessaire** mais **exposé sur `0.0.0.0`** → à restreindre au local |
| 3632 | distcc | distccd | ☠️ CVE-2004-2687 (exécution de code distante) |
| 5432 | PostgreSQL | postgres | ❌ Les applis utilisent MySQL |
| 5900 | VNC | Xtightvnc | ☠️ Bureau distant, mot de passe faible |
| 6000 | X11 | Xtightvnc | ❌ Affichage distant exposé |
| 6667 / 6697 | IRC | UnrealIRCd | ☠️ **Backdoor** (CVE-2010-2075) |
| 8009 / 8180 | AJP / HTTP | Tomcat (jsvc) | ☠️ Tomcat manager (identifiants faibles → RCE) |
| 8787 | DRb (Ruby distribué) | ruby | ☠️ Exécution de code distante |
| 953 / 639 (local) | rndc / statd | named / rpc.statd | ❌ Contrôle local / RPC |

## 4. Dépendances de DVWA et Mutillidae

```
Navigateur (HTTP/80)
      │
      ▼
Apache 2.2.8 ──charge──► PHP ──interprète──► /var/www/dvwa , /var/www/mutillidae
      │                                              │
      │                              requêtes SQL (localhost)
      ▼                                              ▼
                                          MySQL 5.0.51a
```

**Flux strictement nécessaires :**
1. **Entrant** : client → `80/tcp` (Apache) — seul flux entrant métier.
2. **Interne** : Apache/PHP → MySQL. Cette liaison peut se faire en **local**.
   Or MySQL écoute actuellement sur **`0.0.0.0:3306`** (exposé au réseau) alors
   qu'une écoute locale (`127.0.0.1`) suffirait → exposition inutile à corriger.
3. **Administration** : admin → `22/tcp` (SSH), à restreindre à un réseau de confiance.

**Composants à conserver :** Apache (80), MySQL (à rendre local), SSH (22).

## 5. Analyse de la surface d'attaque

### 5.1 Ce qui doit être protégé
- **Apache + PHP (80)** : unique porte d'entrée légitime.
- **MySQL (3306)** : données des applications → **à restreindre à l'écoute locale**.
- **SSH (22)** : administration → clés, root interdit, filtrage, algorithmes modernes.

### 5.2 Ce qui est inutile / dangereux (à éliminer)

| Famille | Services / ports | Risque |
|---|---|---|
| ☠️ **Backdoors directes** | ingreslock 1524, UnrealIRCd 6667/6697, FTP piégé 21 | Shell root immédiat |
| ☠️ **Exécution de code distante** | distccd 3632, Java RMI 1099, DRb 8787, Tomcat 8180/8009, Samba 139/445 | RCE non authentifiée |
| **Protocoles en clair / auth faible** | Telnet 23, r-services 512-514, VNC 5900, TFTP 69 | Vol d'identifiants, MITM |
| **Partage réseau non requis** | Samba 139/445/137/138, NFS 2049, portmap 111 | Accès fichiers, mouvement latéral |
| **Services hors périmètre** | SMTP 25, DNS 53, PostgreSQL 5432, ProFTPD 2121, X11 6000 | Surface et CVE inutiles |

### 5.3 Synthèse
> Sur ~25 ports ouverts, **3 services seulement sont nécessaires** (22, 80, et
> 3306 à rendre local). Le durcissement consiste donc d'abord à **neutraliser les
> backdoors**, puis à **supprimer tous les services inutiles**, à **restreindre
> MySQL au local**, et enfin à durcir SSH, le pare-feu et le moindre privilège —
> en gardant DVWA et Mutillidae fonctionnels.

### 5.4 Périmètre réaliste (important)
Metasploitable 2 (Ubuntu 8.04) est **en fin de vie** : ses dépôts APT sont fermés,
donc Apache/PHP/MySQL **ne sont pas patchables**. « Supprimer toutes les failles »
n'est ni l'objet du TP (DVWA et Mutillidae doivent rester vulnérables et
fonctionnelles) ni atteignable. L'objectif est la **réduction de la surface
d'attaque** et le **durcissement cohérent** ; la correction de fond des versions
relèverait d'une **migration**, à recommander dans le plan.
