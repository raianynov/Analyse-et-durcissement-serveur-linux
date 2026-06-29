**Sécurité des systèmes d'exploitation et des réseaux**

# Travail pratique n° 3
## Analyse et durcissement d'un serveur Linux

| | |
|---|---|
| **Système cible** | Metasploitable 2 (Ubuntu 8.04 LTS) |
| **Document** | Partie 2 — Plan de durcissement |
| **Auteur** | Raian Remir |
| **Date** | Juin 2026 |
| **Version** | 1.0 |
| **Diffusion** | Usage pédagogique — réseau isolé |

---

## Sommaire

1. Neutralisation des portes dérobées
2. Suppression des services superflus
3. Restriction de MySQL à l'écoute locale
4. Durcissement de l'authentification SSH
5. Filtrage réseau (pare-feu)
6. Application du moindre privilège
7. Durcissement des services exposés
8. Sécurisation du système de fichiers
9. Validation finale et synthèse

---

Chaque mesure suit la structure : état initial, mesures appliquées, vérification
(avec la sortie réelle relevée), état final. La cible est Ubuntu 8.04 (SysVinit,
xinetd et inetd, iptables). Avant toute action, un instantané de la machine virtuelle
est réalisé ; après chaque étape, le fonctionnement de DVWA et de Mutillidae est
contrôlé. L'accès s'effectue par `ssh -o HostKeyAlgorithms=+ssh-rsa msfadmin@192.168.58.128`
ou par la console de la machine virtuelle. Les mots de passe indiqués sont des placeholders (<MDP_DVWA>, <MDP_MUTILLIDAE>, <MDP_ROOT>) à remplacer par des mots de passe forts, sans le caractère "!".

## Thème 1 — Neutralisation des backdoors

**État initial.** Cinq portes dérobées actives : ingreslock 1524 (shell root sans
authentification), UnrealIRCd 6667/6697, Java RMI 1099, Ruby DRb 8787 et VNC/X11
5900/6000, lancées par `/etc/rc.local` ; vsftpd 2.3.4 piégé (port 21) lancé par xinetd.

**Mesures.**
```bash
sudo cp /etc/rc.local /etc/rc.local.bak
sudo sed -i '/nohup/ s/^/#/' /etc/rc.local
sudo pkill -f unrealircd; sudo pkill -f rmiregistry; sudo pkill -f druby; sudo pkill Xtightvnc
sudo sed -i 's/disable\s*=\s*no/disable = yes/' /etc/xinetd.d/vsftpd
sudo cp /etc/inetd.conf /etc/inetd.conf.bak
sudo sed -i -r '/^(telnet|tftp|shell|login|exec|ingreslock)/ s/^/#/' /etc/inetd.conf
sudo /etc/init.d/xinetd restart
```

**Vérification.**
```
$ sudo netstat -tulpn | grep -E ':21 |:23 |:1099|:1524|:5900|:6000|:6667|:6697|:8787'
(aucune ligne)

PS> Test-NetConnection <ip_de_la_machine> -Port 1524
TcpTestSucceeded : False
```

**État final.** Les cinq backdoors et les services inetd en clair (telnet,
rexec/rlogin/rsh, tftp) sont neutralisés. La backdoor root ingreslock ne répond plus.

## Thème 2 — Suppression des services inutiles

**État initial.** Services hors périmètre actifs : Samba (139/445/137/138), NFS et
portmap (2049/111), BIND (53), PostgreSQL (5432), Tomcat (8009/8180), distccd (3632),
ProFTPD (2121), Postfix (25).

**Mesures.**
```bash
for s in samba nfs-kernel-server nfs-common portmap bind9 postgresql-8.3 tomcat5.5 distcc proftpd postfix; do sudo /etc/init.d/$s stop; done
for s in samba nfs-kernel-server nfs-common portmap bind9 postgresql-8.3 tomcat5.5 distcc proftpd postfix; do sudo update-rc.d -f $s remove; done
sudo pkill rpc.statd; sudo pkill rpc.mountd; sudo pkill nmbd; sudo pkill named; sudo pkill -9 distccd
```

**Vérification.**
```
$ sudo netstat -tulpn
tcp   0.0.0.0:3306   LISTEN  mysqld
tcp   0.0.0.0:80     LISTEN  apache2
tcp6  :::22          LISTEN  sshd
udp   0.0.0.0:68             dhclient3
```

**État final.** Seuls les trois services nécessaires subsistent. Le port 3306 reste
exposé et sera restreint au thème suivant. Le contrôle porte sur IPv4 et IPv6 :
distccd écoutait encore en IPv6 après l'arrêt du service et a dû être terminé.

## Thème 3 — Restriction de MySQL à l'écoute locale

**État initial.** MySQL écoute sur 0.0.0.0:3306, exposé au réseau, alors que seules
les applications locales l'utilisent.

**Mesures.**
```bash
sudo cp /etc/mysql/my.cnf /etc/mysql/my.cnf.bak
sudo sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/my.cnf
sudo /etc/init.d/mysql restart
```

**Vérification.**
```
$ sudo netstat -tulpn | grep 3306
tcp   127.0.0.1:3306   LISTEN  mysqld

PS> Test-NetConnection <ip_de_la_machine> -Port 3306
TcpTestSucceeded : False
```
DVWA et Mutillidae restent fonctionnelles (connexion MySQL locale).

**État final.** La base n'est accessible qu'en local.

## Thème 4 — Durcissement de l'authentification SSH

**État initial.** `PermitRootLogin yes` et authentification par mot de passe
autorisée. OpenSSH 4.7 n'accepte que les algorithmes ssh-rsa et ssh-dss.

**Mesures.**

Génération de la paire de clés sur le poste d'administration Windows (ed25519 non
supporté par OpenSSH 4.7, on utilise RSA) :
```powershell
ssh-keygen -t rsa -b 2048 -f $env:USERPROFILE\.ssh\msf_rsa
```

Raccourci de connexion dans `%USERPROFILE%\.ssh\config` :
```
Host msf
    HostName <ip_de_la_machine>
    User msfadmin
    HostKeyAlgorithms +ssh-rsa
    PubkeyAcceptedAlgorithms +ssh-rsa
    IdentityFile ~/.ssh/msf_rsa
```

Dépôt de la clé publique sur la VM (authentification par mot de passe, une
dernière fois) :
```powershell
type $env:USERPROFILE\.ssh\msf_rsa.pub | ssh msf "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

La connexion par clé est testée et validée avant de modifier la configuration
serveur. La configuration est réécrite par suppression des directives existantes
puis ajout d'un bloc unique (sed -r requis sur Ubuntu 8.04, qui ne reconnaît pas
sed -E) :
```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sudo sed -i -r '/^[[:space:]]*#?[[:space:]]*(Protocol|PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|PubkeyAuthentication)\b/d' /etc/ssh/sshd_config
printf '\nProtocol 2\nPermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\nPubkeyAuthentication yes\n' | sudo tee -a /etc/ssh/sshd_config
sudo /etc/init.d/ssh restart
```

**Vérification.**
```
$ sudo grep -nE '^(Protocol|PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|PubkeyAuthentication)' /etc/ssh/sshd_config
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes

PS> ssh msf
(session ouverte par clé)

PS> ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no msf
Permission denied (publickey).
```

**État final.** Connexion root interdite, authentification par clé uniquement,
SSHv2 imposé. Le chiffrement reste obsolète (OpenSSH 4.7), limite traitée par le
filtrage réseau du port 22 et, en correction de fond, par la migration.

## Thème 5 — Pare-feu

**État initial.** Aucune règle de filtrage, chaînes en politique ACCEPT.

**Mesures.** Les règles d'autorisation sont ajoutées avant le basculement de la
politique en DROP afin de préserver la session SSH (règle « established »).
```bash
sudo iptables -F
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p icmp -j ACCEPT
sudo iptables -A INPUT -p tcp -s <ip_reseau_de_la_machine>/24 --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT
sudo sh -c 'iptables-save > /etc/iptables.rules'
sudo sed -i 's%^exit 0%iptables-restore < /etc/iptables.rules\nexit 0%' /etc/rc.local
```

**Vérification.**
```
$ sudo iptables -L -n -v
Chain INPUT (policy DROP)
  ACCEPT all  -- lo
  ACCEPT all  -- state RELATED,ESTABLISHED
  ACCEPT icmp
  ACCEPT tcp  -- <ip_reseau_de_la_machine>/24   tcp dpt:22
  ACCEPT tcp  --                   tcp dpt:80
Chain FORWARD (policy DROP)
Chain OUTPUT (policy ACCEPT)
```
SSH et applications toujours fonctionnels.

**État final.** Politique DROP par défaut ; seuls les ports 80 (réseau) et 22
(depuis l'ip réseau de la machine) sont autorisés ; règles rechargées au démarrage.

## Thème 6 — Moindre privilège

**État initial.** Mot de passe par défaut msfadmin ; comptes faibles user et service ;
sudo accordé par le groupe admin.

**Mesures.**
```bash
passwd
sudo passwd -l user
sudo passwd -l service
sudo passwd -l postgres
```

**Vérification.**
```
$ sudo grep -vE '^#|^$' /etc/sudoers
Defaults    env_reset
root    ALL=(ALL) ALL
%admin ALL=(ALL) ALL

$ groups msfadmin
msfadmin adm dialout cdrom floppy audio dip video plugdev fuse lpadmin admin sambashare
```

**État final.** Plus d'identifiants par défaut, comptes faibles verrouillés (user,
service, postgres), élévation de privilèges restreinte au groupe admin.

## Thème 7 — Durcissement des services restants

### Apache

**État initial.** Version exposée dans la bannière, signature active.

**Mesures.**
```bash
sudo cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.bak
printf '\nServerName metasploitable\nServerTokens Prod\nServerSignature Off\nTraceEnable Off\n' | sudo tee -a /etc/apache2/apache2.conf
sudo /etc/init.d/apache2 restart
```

**Vérification.**
```
$ curl -I http://localhost/ | grep -i server
Server: Apache
```

### MySQL

**État initial.** Compte root sans mot de passe ; comptes root@'%' et guest@'%'
accessibles à distance ; applications utilisant le compte root sans mot de passe
(DVWA sur la base dvwa, Mutillidae sur la base metasploit).

**Mesures.** Les comptes applicatifs dédiés sont créés et les configurations
repointées avant la sécurisation de root. Sur Metasploitable, root est défini en
root@'%' : le mot de passe est modifié par UPDATE puis l'hôte restreint à local.
```bash
mysql -u root << 'SQL'
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost' IDENTIFIED BY '<MDP_DVWA>';
GRANT ALL PRIVILEGES ON metasploit.* TO 'mutillidae'@'localhost' IDENTIFIED BY '<MDP_MUTILLIDAE>';
FLUSH PRIVILEGES;
SQL

sudo sed -i "s/\$_DVWA\[ 'db_user' \] *= *'root'/\$_DVWA[ 'db_user' ] = 'dvwa'/" /var/www/dvwa/config/config.inc.php
sudo sed -i "s/\$_DVWA\[ 'db_password' \] *= *''/\$_DVWA[ 'db_password' ] = '<MDP_DVWA>'/" /var/www/dvwa/config/config.inc.php
sudo sed -i "s/\$dbuser *= *'root'/\$dbuser = 'mutillidae'/" /var/www/mutillidae/config.inc
sudo sed -i "s/\$dbpass *= *''/\$dbpass = '<MDP_MUTILLIDAE>'/" /var/www/mutillidae/config.inc

mysql -u root << 'SQL'
UPDATE mysql.user SET Password=PASSWORD('<MDP_ROOT>') WHERE User='root';
UPDATE mysql.user SET Host='localhost' WHERE User='root' AND Host='%';
DELETE FROM mysql.user WHERE User='guest';
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
SQL
```

**Vérification.**
```
$ curl -I http://localhost/ | grep -i server
Server: Apache

$ sudo grep -iE "db_user|db_password" /var/www/dvwa/config/config.inc.php
$_DVWA[ 'db_user' ] = 'dvwa';
$_DVWA[ 'db_password' ] = '<MDP_DVWA>';

$ sudo grep -inE 'dbuser|dbpass' /var/www/mutillidae/config.inc
5:    $dbuser = 'mutillidae';
6:    $dbpass = '<MDP_MUTILLIDAE>';

$ mysql -u root -p<MDP_ROOT> -e "SELECT User,Host FROM mysql.user;"
debian-sys-maint |
dvwa             | localhost
mutillidae       | localhost
root             | localhost
```
DVWA et Mutillidae fonctionnelles avec leurs comptes dédiés.

**État final.** Version Apache masquée ; compte root MySQL protégé et restreint au
local ; comptes anonymes et distants supprimés ; applications cantonnées à leur
base via des comptes dédiés.

## Thème 8 — Sécurisation du système de fichiers

**État initial.** Nombreux binaires SUID/SGID ; partition /tmp sans restriction.

**Mesures.**
```bash
sudo find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
sudo chmod 600 /etc/shadow
echo 'tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0' | sudo tee -a /etc/fstab
sudo mount /tmp
```

**Vérification.**
```
$ ls -l /etc/shadow
-rw------- 1 root shadow 1213 /etc/shadow

$ mount | grep /tmp
tmpfs on /tmp type tmpfs (rw,noexec,nosuid,nodev)
```

**État final.** Exécution et bit SUID interdits dans /tmp, fichiers sensibles
protégés, inventaire SUID établi.

## Validation finale de l'état du système

Après application des huit thèmes, une vérification globale confirme la cohérence de
l'état final : seuls les trois services nécessaires sont exposés (dont MySQL en
écoute locale uniquement), le pare-feu applique sa politique DROP, SSH est restreint
à la clé, et les deux applications restent fonctionnelles.

```
$ sudo netstat -tulpn
tcp   127.0.0.1:3306   LISTEN  mysqld     (MySQL, local uniquement)
tcp   0.0.0.0:80       LISTEN  apache2    (Apache, metier)
tcp6  :::22            LISTEN  sshd       (SSH, filtre <ip_reseau_de_la_machine>/24)
udp   0 0.0.0.0:68     LISTEN  dhclient   (service dhcp)

$ sudo iptables -L -n | grep policy
Chain INPUT (policy DROP)
Chain FORWARD (policy DROP)
Chain OUTPUT (policy ACCEPT)

# Depuis le poste d'administration : ports non metier injoignables
PS> Test-NetConnection <ip_de_la_machine> -Port 1524   # ingreslock (backdoor)
TcpTestSucceeded : False
PS> Test-NetConnection <ip_de_la_machine> -Port 3306   # MySQL
TcpTestSucceeded : False
PS> Test-NetConnection <ip_de_la_machine> -Port 80     # Apache
TcpTestSucceeded : True

# Applications toujours servies
$ curl -s -o /dev/null -w "%{http_code}\n" -L http://<ip_de_la_machine>/dvwa/
200
```

Cette validation synthétise l'aboutissement du durcissement : sur environ vingt-cinq
ports initiaux, trois services nécessaires subsistent, MySQL n'est plus exposé au
réseau, les backdoors ne répondent plus, et DVWA comme Mutillidae restent
accessibles.

## Récapitulatif

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
fonctionnelles. La correction de fond des versions, non réalisable sur Ubuntu 8.04,
relève d'une migration vers un système supporté.
