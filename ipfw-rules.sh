#!/bin/sh

# Flush out the list before we begin.
ipfw -q -f flush

# NIC Internet
eif=vtnet0
# Nic LAN
lif=vtnet1
# Nic OpenVpn
vif=tun0
# Nic Wireguard
wif=wg0
# IP WAN
wanip="159.203.56.10"
# NAT
skip="skipto 2500"
# build rule prefix
IPF="ipfw -q add"
# Manter estado da conexao
ks="keep-state"
# Portas de saída tcp confiaveis
good_tcp="46666,25,37,53,80,443,110"
# IPs wireguard clients
wireguard_clients="10.96.100.0/24"
# Wireguard port
wg_port="{51820}"

#permitidno reinjeçao de pacotes
ipfw disable one_pass
#Configuranaod instancia NAT
ipfw -q nat 1 config if $eif same_ports unreg_only reset

#loopback 
$IPF 5 allow all from any to any via lo0

# LAN
$IPF 109 allow all from any to any via $lif
#OpenVPN
$IPF 110 allow all from any to any via $vif
#Wireguard
$IPF 111 allow all from any to any via $wif

# Remontagem de pacotes de entrada
$IPF 690 reass all from any to any in

# NAT de qualquer pkt de entrada
$IPF 699 nat 1 ip from any to any in via $eif

# statefull - permite passagem do pkt se corresponder a uma entrada na tabela de regras dinamicas
$IPF 700 check-state

##
### Resgras de saida para conexoes stateful com a Internet
##

# FTP
$IPF 1000 $skip tcp from any to any 20 out setup $ks
$IPF 1005 $skip tcp from any to any 21 out setup $ks
# SSH
$IPF 1010 $skip tcp from any to any 46666 out setup $ks
# Email
$IPF 1015 $skip tcp from any to any 25 out setup $ks
# DNS
$IPF 1020 $skip udp from any to any 53 out $ks 
$IPF 1025 $skip tcp from any to any 53 out setup $ks
# 80 e 443
$IPF 1030 $skip tcp from any to any 80 out setup $ks
$IPF 1035 $skip tcp from any to any 443 out setup $ks
# icmp
$IPF 1036 $skip icmp from any to any out $sk
# NTP
$IPF 1055 $skip udp from any to any 123 out $ks


##
### Regras e entrada 
##

## Bloqueando
#
# bloqueando trafico de endereços reservados
$IPF 1500 deny all from 192.168.0.0/16 to any in via $eif # RFC 1918 private IP
$IPF 1501 deny all from 172.16.0.0/12 to any in via $eif # RFC 1918 private IP
$IPF 1502 deny all from 10.0.0.0/8 to any in via $eif # RFC 1918 private IP
$IPF 1503 deny all from 127.0.0.0/8 to any in via $eif # loopback
$IPF 1504 deny all from 0.0.0.0/8 to any in via $eif # loopback
$IPF 1505 deny all from 169.254.0.0/16 to any in via $eif # DHCP auto-config
$IPF 1506 deny all from 224.0.0.0/3 to any in via $eif # Class D & E multicast
# bloquenaod ident
$IPF 1520 deny tcp from any to any 113 in via $eif
# bloqueando Netbios
$IPF 1540 deny tcp from any to any 137 in via $eif
$IPF 1541 deny tcp from any to any 138 in via $eif
$IPF 1542 deny tcp from any to any 139 in via $eif
$IPF 1543 deny tcp from any to any 81 in via $eif

## Permitindo
#
# Permitindo tipos ICMP com limitaçao
$IPF 1560 allow icmp from any to $wanip in via $eif icmptypes 0,8,11 limit src-addr 2
# Permitindo HTTP com limitacao
$IPF 1570 allow tcp from any to $wanip 80 in via $eif setup limit src-addr 2
# Permitindo HTTPs com limitacao
$IPF 1571 allow tcp from any to $wanip 443 in via $eif setup limit src-addr 2
# Permitindo SSH
$IPF 1573 allow tcp from any to any 46666 in setup limit src-addr 4
# Tor e OBFS4
$IPF 1574 allow tcp from any to any 36666 in 
$IPF 1575 allow tcp from any to any 26666 in
# OpenVPN
$IPF 1580 allow ip from any to any 1194 in $ks
# Wireguard
$IPF 1585 allow ip from any to any 51820 in $ks


# Permitindo conexoes ja estabelecidas
$IPF 1999 allow all from any to any established


##
### Fim dos fluxos
##

# deny and log everything fora do skip
$IPF 2000 deny log all from any to any

# Skipto para saida das regras stateful NAT
$IPF 2500 nat 1 ip from any to any out via $eif
$IPF 2501 allow ip from any to any 

#Negando todo o resto
$IPF 3000 deny log all from any to any
