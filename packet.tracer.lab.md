- Parking VLAN: 42
- STP Mode: RSTP
- ESSID: Heart-of-Gold
- Wireless Auth: EAP
- Data VLAN: 10 (10.0.10.0/24) GW: .1
- Voice VLAN: 11 (10.0.11.0/24) GW: .1
- Data VLAN: 20 (10.0.20.0/24) GW: .1
- Voice VLAN: 21 (10.0.21.0/24) GW: .1
- Data VLAN: 30 (10.0.30.0/24) GW: .1
- Data VLAN: 101 (10.0.101.0/24) GW: .1
- Data VLAN: 102 (10.0.102.0/24) GW: .1
- DHCP on CME
- No DTP
- DNS = lab.local

#### SW1-1
- Port security 5 MAC addresses/port
- DAI/DHCP Guard
- Management: 192.168.255.2/24
- Data VLAN: 10
- Voice VLAN: 11


#### SW2-1
- Port security 5 MAC addresses/port
- DAI/DHCP Guard
- Management: 192.168.255.6/24
- Data VLAN: 20
- Voice VLAN: 21


#### DC1
- Port security 1 MAC address/port
- DAI/DHCP Guard
- Management: 192.168.255.3/24
- Data VLAN: 30
  ###### Syslog: 10.0.30.10
  ###### DNS: 10.0.30.11
  ###### NTP: 10.0.30.12
  ###### AAA: 10.0.30.13
  ###### WWW: 10.0.30.14
  ###### CME: 10.0.30.15
  ###### WLC: 10.0.30.16

#### MLS1
- DAI/DHCP Guard
- Management: 192.168.255.4/24
- OSPF Area: 2

#### MLS2
- Root Bridge
- DAI/DHCP Guard
- Management: 192.168.255.5/24
- OSPF Area: 2

#### AP1
- Management: 192.168.255.6/24
- Data VLAN: 101


#### AP2
- Management: 192.168.255.7/24
- Data VLAN: 102

####  CR1
- VRRP
- OSPF Area: 1

#### CR2
- HSRP
- OSPF Area: 1


#### PH1-1
- DN: 1001


#### PH1-2
- DN: 1002


#### PH2-1
- DN: 2001


#### PH2-2
- DN: 2002
