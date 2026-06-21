# Partie 2 — Plan de durcissement (Metasploitable 2)

Format par mesure : **état initial → modification → état final**.
Cible : Ubuntu 8.04 (SysVinit, xinetd/inetd, iptables).
Précautions : snapshot avant de commencer ; après chaque étape, vérifier que
**DVWA** (`/dvwa/`) et **Mutillidae** (`/mutillidae/`) répondent toujours.
Accès : `ssh -o HostKeyAlgorithms=+ssh-rsa msfadmin@192.168.58.128` ou console VMware.

> **Note** : les mots de passe sont des placeholders (`<MDP_DVWA>`, `<MDP_MUTILLIDAE>`,
> `<MDP_ROOT>`) à remplacer par des mots de passe forts — **sans `!`** (expansion
> d'historique bash en ligne de commande).

---

## Thème 1 — Neutraliser les backdoors

**Initial** : ingreslock 1524 (shell root sans auth), UnrealIRCd 6667/6697, Java RMI
1099, Ruby DRb 8787, VNC/X11 5900/6000 (lancés par `/etc/rc.local`), vsftpd 2.3.4
piégé 21 (xinetd).

```bash
# Backdoors lancées par rc.local
sudo cp /etc/rc.local /etc/rc.local.bak
sudo sed -i '/nohup/ s/^/#/' /etc/rc.local
sudo pkill -f unrealircd; sudo pkill -f rmiregistry; sudo pkill -f druby; sudo pkill Xtightvnc
# vsftpd piégé (xinetd)
sudo sed -i 's/disable\s*=\s*no/disable = yes/' /etc/xinetd.d/vsftpd
# inetd : ingreslock, telnet, r-services, tftp  (sed -r : Ubuntu 8.04 ne connaît pas -E)
sudo cp /etc/inetd.conf /etc/inetd.conf.bak
sudo sed -i -r '/^(telnet|tftp|shell|login|exec|ingreslock)/ s/^/#/' /etc/inetd.conf
sudo /etc/init.d/xinetd restart
```

**Vérification** : `sudo netstat -tulpn | grep -E ':21 |:23 |:1099|:1524|:5900|:6000|:6667|:6697|:8787'` → vide.
Preuve attaquant : `Test-NetConnection 192.168.58.128 -Port 1524` → `False` (avant : `True`).

> **Preuve relevée** (machine propre, IP 192.168.58.128) :
> - `netstat` filtré sur les ports backdoors → **aucune ligne** (tous fermés).
> - `Test-NetConnection ... -Port 1524` → `TcpTestSucceeded : False`
>   (la backdoor root ingreslock ne répond plus).

**Final** : 5 backdoors + services inetd en clair (telnet, rexec/rlogin/rsh, tftp) neutralisés.

---

## Thème 2 — Supprimer les services inutiles

**Initial** : Samba (139/445/137/138), NFS+portmap (2049/111 + ports RPC dynamiques),
BIND (53), PostgreSQL (5432), Tomcat (8009/8180), distccd (3632), ProFTPD (2121),
Postfix (25).

```bash
for s in samba nfs-kernel-server nfs-common portmap bind9 postgresql-8.3 tomcat5.5 distcc proftpd postfix; do sudo /etc/init.d/$s stop; done
for s in samba nfs-kernel-server nfs-common portmap bind9 postgresql-8.3 tomcat5.5 distcc proftpd postfix; do sudo update-rc.d -f $s remove; done
sudo pkill rpc.statd; sudo pkill rpc.mountd; sudo pkill nmbd; sudo pkill named; sudo pkill -9 distccd
```

**Vérification** : `sudo netstat -tulpn` (IPv4 **et** IPv6) → ne restent que 80, 22,
3306 et le client DHCP (udp/68).

> **Preuve relevée** (`sudo netstat -tulpn` après purge) :
> ```
> tcp   0.0.0.0:3306   LISTEN  mysqld     (encore exposé → Thème 3)
> tcp   0.0.0.0:80     LISTEN  apache2
> tcp6  :::22          LISTEN  sshd
> udp   0.0.0.0:68             dhclient3
> ```
> Plus aucune trace de Samba, NFS/RPC, BIND, PostgreSQL, Tomcat, distccd, ProFTPD, Postfix.

**Final** : seuls les 3 services nécessaires subsistent.
> distccd écoutait en IPv6 (`tcp6 :::3632`) après l'arrêt du service → toujours
> vérifier les deux piles dans `netstat`.

---

## Thème 3 — Restreindre MySQL au local

**Initial** : MySQL en écoute sur `0.0.0.0:3306` (exposé) ; seules les applis locales l'utilisent.

```bash
sudo cp /etc/mysql/my.cnf /etc/mysql/my.cnf.bak
sudo sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/my.cnf
sudo /etc/init.d/mysql restart
```

**Vérification** : `sudo netstat -tulpn | grep 3306` → `127.0.0.1:3306` ;
`Test-NetConnection 192.168.58.128 -Port 3306` → `False`.

> **Preuve relevée** :
> - `netstat | grep 3306` → `tcp 127.0.0.1:3306 LISTEN mysqld`
> - `Test-NetConnection ... -Port 3306` → `TcpTestSucceeded : False`
> - DVWA et Mutillidae toujours fonctionnelles (connexion MySQL locale).

**Final** : base accessible uniquement en local.

---

## Thème 4 — Durcir l'authentification SSH

**Initial** : `PermitRootLogin yes`, authentification par mot de passe autorisée.

```bash
# Poste admin (Windows) : clé RSA (OpenSSH 4.7 ne supporte pas ed25519)
#   ssh-keygen -t rsa -b 2048 -f %USERPROFILE%\.ssh\msf_rsa
#   puis dépôt de msf_rsa.pub dans ~/.ssh/authorized_keys (via mot de passe, une dernière fois)

# Côté VM : bloc propre (supprimer les lignes existantes puis ajouter ; sed -r)
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sudo sed -i -r '/^[[:space:]]*#?[[:space:]]*(Protocol|PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|PubkeyAuthentication)\b/d' /etc/ssh/sshd_config
printf '\n# Durcissement TP3\nProtocol 2\nPermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\nPubkeyAuthentication yes\n' | sudo tee -a /etc/ssh/sshd_config
sudo /etc/init.d/ssh restart
```

**Vérification** : connexion par clé → shell ouvert ;
`ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no ...` → `Permission denied (publickey)`.

> **Preuve relevée** :
> - `sudo grep -nE '...' /etc/ssh/sshd_config` → 5 lignes uniques :
>   `Protocol 2`, `PermitRootLogin no`, `PasswordAuthentication no`,
>   `PermitEmptyPasswords no`, `PubkeyAuthentication yes`.
> - `ssh msf` → shell ouvert (clé acceptée).
> - `ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no msf`
>   → `Permission denied (publickey)`.

**Final** : root interdit, authentification par clé uniquement, SSHv2 forcé.
> Limite : crypto SSH obsolète imposée par OpenSSH 4.7 (Ubuntu 8.04) → atténuée par
> le filtrage réseau du port 22 ; correction de fond = migration.

---

## Thème 5 — Pare-feu iptables

**Initial** : aucune règle (chaînes en `ACCEPT`).

```bash
sudo iptables -F
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p icmp -j ACCEPT
sudo iptables -A INPUT -p tcp -s 192.168.58.0/24 --dport 22 -j ACCEPT   # SSH (admin)
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT                      # HTTP (applis)
sudo iptables -P INPUT DROP; sudo iptables -P FORWARD DROP; sudo iptables -P OUTPUT ACCEPT
# Persistance au reboot
sudo sh -c 'iptables-save > /etc/iptables.rules'
sudo sed -i 's%^exit 0%iptables-restore < /etc/iptables.rules\nexit 0%' /etc/rc.local
```

**Vérification** : `sudo iptables -L -n -v` → `policy DROP` sur INPUT/FORWARD ;
SSH et applis toujours fonctionnels.

> **Preuve relevée** (`sudo iptables -L -n -v`) :
> ```
> Chain INPUT (policy DROP)
>   ACCEPT all  -- lo
>   ACCEPT all  -- state RELATED,ESTABLISHED
>   ACCEPT icmp
>   ACCEPT tcp  -- 192.168.58.0/24  dpt:22
>   ACCEPT tcp  -- dpt:80
> Chain FORWARD (policy DROP) ; Chain OUTPUT (policy ACCEPT)
> ```
> `ssh msf` et DVWA/Mutillidae toujours fonctionnels.

**Final** : seuls 80 (réseau) et 22 (depuis `192.168.58.0/24`) autorisés ; règles persistées.
> Ajouter les règles d'autorisation **avant** de basculer la politique en DROP pour
> ne pas couper la session SSH (la règle « established » la préserve).

---

## Thème 6 — Moindre privilège

**Initial** : mot de passe par défaut `msfadmin/msfadmin` ; comptes faibles `user`,
`service` ; `sudo` accordé via le groupe `admin`.

```bash
passwd                       # mot de passe d'admin fort (SANS '!') — sert à sudo/console
sudo passwd -l user
sudo passwd -l service
sudo passwd -l postgres      # compte d'un service supprimé au Thème 2
```

**Vérification** : `sudo grep -vE '^#|^$' /etc/sudoers` → `%admin ALL=(ALL) ALL` ;
`sudo -k; sudo -v` redemande et accepte le nouveau mot de passe.

> **Preuve relevée** :
> - `sudo grep -vE '^#|^$' /etc/sudoers` → `root ALL=(ALL) ALL` et `%admin ALL=(ALL) ALL`.
> - `groups msfadmin` → `... admin ...` (habilité à `sudo`).
> - Mot de passe par défaut changé ; comptes `user`, `service`, `postgres` verrouillés.

**Final** : plus d'identifiants par défaut, comptes faibles verrouillés, élévation
restreinte au groupe `admin`.

---

## Thème 7 — Durcir les services restants (Apache + MySQL)

### Apache
```bash
sudo cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.bak
printf '\n# Durcissement TP3\nServerName metasploitable\nServerTokens Prod\nServerSignature Off\nTraceEnable Off\n' | sudo tee -a /etc/apache2/apache2.conf
sudo /etc/init.d/apache2 restart
```
**Vérification** : `curl -I http://localhost/ | grep -i server` → `Server: Apache` (version masquée).

### MySQL
**Initial** : root **sans mot de passe** ; `root@'%'` et `guest@'%'` (accès distant) ;
les applis utilisent `root` sans mot de passe (DVWA → base `dvwa`, Mutillidae → base `metasploit`).

> **Ordre crucial** : créer les comptes dédiés et repointer les configs **avant** de
> sécuriser root, sinon les applis perdent l'accès. **Aucun `!`** dans les mots de
> passe (expansion d'historique bash).

```bash
# 1) Comptes applicatifs dédiés, limités à leur base (moindre privilège)
mysql -u root << 'SQL'
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost' IDENTIFIED BY '<MDP_DVWA>';
GRANT ALL PRIVILEGES ON metasploit.* TO 'mutillidae'@'localhost' IDENTIFIED BY '<MDP_MUTILLIDAE>';
FLUSH PRIVILEGES;
SQL

# 2) Repointer les configs des applis (sed sûr, pas de '!')
sudo sed -i "s/\$_DVWA\[ 'db_user' \] *= *'root'/\$_DVWA[ 'db_user' ] = 'dvwa'/" /var/www/dvwa/config/config.inc.php
sudo sed -i "s/\$_DVWA\[ 'db_password' \] *= *''/\$_DVWA[ 'db_password' ] = '<MDP_DVWA>'/" /var/www/dvwa/config/config.inc.php
sudo sed -i "s/\$dbuser *= *'root'/\$dbuser = 'mutillidae'/" /var/www/mutillidae/config.inc
sudo sed -i "s/\$dbpass *= *''/\$dbpass = '<MDP_MUTILLIDAE>'/" /var/www/mutillidae/config.inc

# 3) Sécuriser root et nettoyer (APRÈS le repointage)
#    NB Metasploitable : root existe en root@'%' (et non root@'localhost').
#    On change le mot de passe par UPDATE (indépendant de l'hôte), puis on
#    restreint root à un accès local, et on supprime les comptes anonymes/distants.
mysql -u root << 'SQL'
UPDATE mysql.user SET Password=PASSWORD('<MDP_ROOT>') WHERE User='root';
UPDATE mysql.user SET Host='localhost' WHERE User='root' AND Host='%';
DELETE FROM mysql.user WHERE User='guest';
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
SQL
```

**Vérification** :
```
mysql -u root -p<MDP_ROOT> -e "SELECT User,Host FROM mysql.user;"
  -> root@localhost, dvwa@localhost, mutillidae@localhost, debian-sys-maint
     (plus de root@'%' ni guest)
```
DVWA et Mutillidae se chargent sans erreur (comptes dédiés).

> **Preuve relevée** :
> - `curl -I http://localhost/ | grep -i server` → `Server: Apache` (version masquée).
> - Configs repointées : DVWA `'dvwa'`/`'<MDP_DVWA>'`, Mutillidae `'mutillidae'`/`'<MDP_MUTILLIDAE>'`.
> - `SELECT User,Host FROM mysql.user` → `root@localhost`, `dvwa@localhost`,
>   `mutillidae@localhost`, `debian-sys-maint` (root local, sans `root@'%'` ni `guest`).
> - DVWA et Mutillidae fonctionnelles avec leurs comptes dédiés.

> ⚠️ Sur Metasploitable, root est `root@'%'` (et non `root@'localhost'`) : changer le
> mot de passe par `UPDATE mysql.user ... WHERE User='root'` puis restreindre l'hôte,
> sinon `SET PASSWORD FOR 'root'@'localhost'` échoue (ERROR 1133) et supprime root.
> Récupération : mode `--skip-grant-tables` puis recréation de `root@'localhost'`.

**Final** : version Apache masquée ; root MySQL protégé et local ; comptes anonymes
et distants supprimés ; applis cantonnées à leur base via comptes dédiés.

---

## Thème 8 — Sécuriser le système de fichiers

**Initial** : nombreux binaires SUID/SGID ; `/tmp` sans restriction de montage.

```bash
# Audit des binaires SUID/SGID (à examiner, retirer le bit des non essentiels)
sudo find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
# Protéger les fichiers sensibles
sudo chmod 600 /etc/shadow
# Durcir /tmp : interdire exécution / SUID / périphériques
echo 'tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0' | sudo tee -a /etc/fstab
sudo mount /tmp
```

**Vérification** : `mount | grep /tmp` → `noexec,nosuid,nodev` ;
`ls -l /etc/shadow` → `-rw-------`.

> **Preuve relevée** :
> - `ls -l /etc/shadow` → `-rw------- 1 root shadow` (accès retiré aux autres).
> - `mount | grep /tmp` → `tmpfs on /tmp type tmpfs (rw,noexec,nosuid,nodev)`.

**Final** : exécution et SUID interdits dans `/tmp`, fichiers sensibles protégés,
inventaire SUID documenté.

---

## Récapitulatif

| # | Mesure | Impact métier |
|---|---|---|
| 1 | Backdoors neutralisées (ingreslock, UnrealIRCd, RMI, DRb, vsftpd, VNC) | aucun |
| 2 | Services inutiles supprimés (Samba, NFS, BIND, PostgreSQL, Tomcat, distccd, ProFTPD, Postfix) | aucun |
| 3 | MySQL en écoute locale (127.0.0.1) | aucun |
| 4 | SSH par clé, root interdit, SSHv2 | admin par clé |
| 5 | Pare-feu DROP par défaut (80 + 22 restreint) | aucun |
| 6 | Mot de passe par défaut changé, comptes faibles verrouillés | aucun |
| 7 | Apache + MySQL durcis, comptes applicatifs dédiés | applis préservées |
| 8 | `/tmp` durci, SUID audité, droits sensibles restreints | aucun |

**Résultat** : passage de ~25 services exposés (dont 5 backdoors root) à **3 services
nécessaires durcis**, DVWA et Mutillidae restant fonctionnelles.
**Limite** : Ubuntu 8.04 non patchable (dépôts fermés) → la correction de fond des
versions (Apache/PHP/MySQL) relève d'une **migration**, recommandée.
