# man
#!/usr/bin/en python
#-*- coding: utf-8 -*-

import subprocess
import os
import time
from shutil import copytree, copy

DIR = os.path.dirname(os.path.realpath(__file__))

#Création du fichier Vars qui contiendra les informations
#du certificat.

vars = {
        "set_var EASYRSA_REQ_COUNTRY"   : "FR",
        "set_var EASYRSA_REQ_PROVINCE"  : "Ip",
        "set_var EASYRSA_REQ_CITY"      : "Paris",
        "set_var EASYRSA_REQ_ORG"       : "C",
        "set_var EASYRSA_REQ_EMAIL"     : "p@live.fr",
        "set_var EASYRSA_REQ_OU"        : "O"
        }

#Fonction qui permet d'appeler une commande pour installer 
#les packages sur la machine OpenVpn.
#apt_command reçoit un objet cmd , print  permet d'imprimer
#la commande reçu, le programme crée un Thread qui sera exécuter p$
#on attend la fin du Thread, process.communicate est destiné à la $
#au cas ou le Thread échoue, process communicate renvoit la sortie$
#puis il retourne à la fin du test ! = 0, le shell renvoit 0 si to$
#sert juste à vérifier ça.

def execute_apt_command(cmd):
    print(cmd)
    process = subprocess.Popen(cmd, shell=True, executable="/bin/bash")
    process.wait()
    out, err = process.communicate()

    rc = process.returncode
    #print("return code", rc)
    if rc != 0:
        print(cmd + ": command failed with error code " + str(rc))
        exit(rc)
    return out
#Fonction qui permet de faire appel à des programmes externes 
#Même principe que la fonction apt_command, mais l'objet cmd est une commande
#avec plusieurs arguments,stdin et stdout pour les erreurs, renvoi 0 si tout s'est bien passé

def execute_command(cmd):
    print(cmd)
    cmd_list = cmd.split(" ")
    print(cmd_list)
    process = subprocess.Popen(cmd_list, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out, err = process.communicate()

    process.stdin.close()
    rc = process.returncode
    #print("return code", rc)
#!/usr/bin/en python
#-*- coding: utf-8 -*-

import subprocess
import os
import time
from shutil import copytree, copy

DIR = os.path.dirname(os.path.realpath(__file__))

#Création du fichier Vars qui contiendra les informations
#du certificat.

vars = {
        "set_var EASYRSA_REQ_COUNTRY"   : "FR",
        "set_var EASYRSA_REQ_PROVINCE"  : "Ip",
        "set_var EASYRSA_REQ_CITY"      : "Paris",
        "set_var EASYRSA_REQ_ORG"       : "C",
        "set_var EASYRSA_REQ_EMAIL"     : "p@live.fr",
        "set_var EASYRSA_REQ_OU"        : "O"
        }

#Fonction qui permet d'appeler une commande pour installer 
#les packages sur la machine OpenVpn.
#apt_command reçoit un objet cmd , print  permet d'imprimer
#la commande reçu, le programme crée un Thread qui sera exécuter p$
#on attend la fin du Thread, process.communicate est destiné à la $
#au cas ou le Thread échoue, process communicate renvoit la sortie$
#puis il retourne à la fin du test ! = 0, le shell renvoit 0 si to$
#sert juste à vérifier ça.

def execute_apt_command(cmd):
    print(cmd)
    process = subprocess.Popen(cmd, shell=True, executable="/bin/bash")
    process.wait()
    out, err = process.communicate()

    rc = process.returncode
    #print("return code", rc)
    if rc != 0:
        print(cmd + ": command failed with error code " + str(rc))
        exit(rc)
    return out
#Fonction qui permet de faire appel à des programmes externes 
#Même principe que la fonction apt_command, mais l'objet cmd est une commande
#avec plusieurs arguments,stdin et stdout pour les erreurs, renvoi 0 si tout s'est bien passé

def execute_command(cmd):
    print(cmd)
    cmd_list = cmd.split(" ")
    print(cmd_list)
    process = subprocess.Popen(cmd_list, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out, err = process.communicate()

    process.stdin.close()
    rc = process.returncode
    #print("return code", rc)
    if rc != 0:
        print(cmd + ": command failed with error code " + str(rc))
        exit(rc)
    return out
#Fonction qui permet la gestion de l'outil Easy-rsa
def execute_check_call(cmd):
    print(cmd)
    cmd_list = cmd.split(" ")
    print(cmd_list)
    subprocess.check_call(cmd_list, cwd=os.getcwd())

#test purpose only
#print(DIR)
#execute_command("openssl genrsa -des3 -out /tmp/private.pem 2048")
#execute_command("ls -la /tmp/private.pem")
#Exécution de l'ip forward qui servira à autoriser le forwarding
#des paquets. 
#Ouverture du fichier cd /etc/sysctl.d/NAT.conf  
#Ecriture du forwarding net.ipv4.ip_forward=1
#Fermeture du répertoire
#Exécution de la fonction def execute_command
#Mise à jour d système
#Installation des paquets nécessaire (openvpn, reasy-rsa, net-tools, openssh-server, iptables-peristent) 
file = open("/etc/sysctl.d/NAT.conf", "w")
file.write("net.ipv4.ip_forward=1")
file.close()
execute_command("sysctl -p /etc/sysctl.d/NAT.conf")
execute_apt_command("apt-get update")
execute_apt_command("apt-get install -y openvpn easy-rsa net-tools openssh-server iptables-persistent")

#Copy du fichier sshd_config
#installation d"OpenVpn à partir du dépot 
#Ici on décompresse le fichier
#EasyRsa-3.0.4.tgz
copy(DIR + "/sshd_config", "/etc/")
execute_command("wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.4/EasyRSA-3.0.4.tgz")
execute_command("tar -xf EasyRSA-3.0.4.tgz")


#CA configuration
os.mkdir("/etc/openvpn/CA")

#Copie de façon récursive
copytree(DIR + "/EasyRSA-3.0.4", "/etc/openvpn/CA/easy-rsa")

os.chdir("/etc/openvpn/CA/easy-rsa")
os.symlink("openssl-easyrsa.cnf", "openssl.cnf")
copy(DIR + "/vars", "vars")

#Modifier vars

#set_var EASYRSA_REQ_COUNTRY     "FR"
#set_var EASYRSA_REQ_PROVINCE    "ip"
#set_var EASYRSA_REQ_CITY        "Paris"
#set_var EASYRSA_REQ_ORG         "C"
#set_var EASYRSA_REQ_EMAIL       "p@live.fr"
#set_var EASYRSA_REQ_OU          "O"

#Création de la privé
execute_command("./easyrsa init-pki")

#Crréation de la clé build-ca avec l'option nopass
#Qui laissera la clé sans chiffrement , car exécuter via un programme automatisé
execute_check_call("./easyrsa build-ca nopass")



# OPENVPN config
copytree(DIR + "/EasyRSA-3.0.4", "/etc/openvpn/easy-rsa")
os.chdir("/etc/openvpn/easy-rsa")

execute_command("./easyrsa init-pki")
execute_check_call("./easyrsa gen-req srvcert nopass")

#Création du dossier Keys 
#Copie de la clé svrcer.ley vers le répetoire /etc/openvpn/easy-rsa/keys
#Copie de la clé srvcer.key vers le répertoire /etc/openvpn/
os.mkdir("/etc/openvpn/easy-rsa/keys")
copy("/etc/openvpn/easy-rsa/pki/private/srvcert.key", "/etc/openvpn/easy-rsa/keys")
copy("/etc/openvpn/easy-rsa/pki/private/srvcert.key", "/etc/openvpn/")
copy("/etc/openvpn/easy-rsa/pki/reqs/srvcert.req", DIR + "/")
copy(DIR + "/server.conf", "/etc/openvpn/")


#CA config
os.chdir("/etc/openvpn/CA/easy-rsa")

execute_check_call("./easyrsa import-req " + DIR + "/srvcert.req srvcert")

execute_check_call("./easyrsa sign-req server srvcert")

copy("pki/issued/srvcert.crt", DIR + "/")
copy("pki/ca.crt", DIR + "/")


# Création du répertoire easy-rsa
#Copie de la clé srvcert.crt dans le dossier cd /etc/eas/-rsa/keys
#Copie de la cla ca.crt dans le dossier cd /etc/easy-rsa/keys
#Copie de la clé srvcert.crt dans le dossier cd /etc/openvpn
#Copie de la clé ca.crt dans le dossier cd /etc/openvpn
os.chdir("/etc/openvpn/easy-rsa")
copy(DIR + "/srvcert.crt", "/etc/openvpn/easy-rsa/keys")
copy(DIR + "/ca.crt", "/etc/openvpn/easy-rsa/keys")
copy(DIR + "/srvcert.crt", "/etc/openvpn/")
copy(DIR + "/ca.crt", "/etc/openvpn/")

#Génération de la clé Diffie-Hellman
execute_check_call("./easyrsa gen-dh")

#Génération de la clé Ta.key
#Copie de la clé ta.key dans le répertoire cd /etc/openvpn/easy-rsa/keys
#Copie de la clé ta.key dans le répertoire cd etc/openvpn
#Copie de la clé privé dans le dossier cd/etc/openvpn
#Copie de la clé privé dans le dossier cd /etc/openvpn/easy-rsa/keys/dh2048.pem
#Copie de la clé privé dans le dossier cd /etc/openvpn/easy-rsa/keys/dh.pem 
execute_command("openvpn --genkey --secret ta.key")
copy("ta.key", "/etc/openvpn/")
copy("ta.key", "/etc/openvpn/easy-rsa/keys")
copy("pki/dh.pem", "/etc/openvpn/")
copy("pki/dh.pem", "/etc/openvpn/easy-rsa/keys/dh2048.pem")
copy("pki/dh.pem", "/etc/openvpn/easy-rsa/keys/dh.pem")

#Règles Iptables qui autorise en entrer le port 22
execute_command("iptables -t filter -A INPUT -p tcp --destination-port 22 -j ACCEPT")

#Règles Iptables qui autorise en sortie le port 22
execute_command("iptables -t filter -A OUTPUT -p tcp --destination-port 22 -j ACCEPT")

#Enregistrement des règles iptables
result = execute_command("iptables-save")

#Répetoire ou sont enregistrées les rèles iptables
file = open("/etc/iptables/rules.v4", "w")
file.write(result)
file.close()

execute_command("systemctl start openvpn")

#execute_command("openvpn /etc/openvpn/server.conf")
#Copie du fichier et remplacement du fichier server.conf dans le répertoire cd /etc/openvpn/server.conf
#Affiche à l'écran Openvpn started
#5 secondes avant l'affichage Openvp,
subprocess.Popen(["openvpn", "/etc/openvpn/server.conf"])
print("openvpn started")
time.sleep(5)

#Affiche l'interface d'OpenVpn
execute_command("ifconfig tun0")

