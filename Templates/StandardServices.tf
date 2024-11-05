resource "nsxt_policy_service" "MS_RPC_TCPv2" {
  description  = "MS_RPC_TCPv2"
  display_name = "MS_RPC_TCPv2"

  l4_port_set_entry {
    display_name      = "MS_RPC_TCPv2"
    description       = "MS_RPC_TCPv2"
    protocol          = "TCP"
    destination_ports = ["135","1024-5000","49152-65535"]
  }
}
resource "nsxt_policy_service" "MS_RPC_UDPv2" {
  description  = "MS_RPC_UDPv2"
  display_name = "MS_RPC_UDPv2"

  l4_port_set_entry {
    display_name      = "MS_RPC_UDPv2"
    description       = "MS_RPC_UDPv2"
    protocol          = "UDP"
    destination_ports = ["135","1024-5000","49152-65535"]
  }
}
resource "nsxt_policy_service" "SUN_RPC_TCPv2" {
  description  = "SUN_RPC_TCPv2"
  display_name = "SUN_RPC_TCPv2"

  l4_port_set_entry {
    display_name      = "SUN_RPC_TCPv2"
    description       = "SUN_RPC_TCPv2"
    protocol          = "TCP"
    destination_ports = ["111","665-1023"]
  }
}
resource "nsxt_policy_service" "ORACLE_TNSv2" {
  description  = "ORACLE_TNSv2"
  display_name = "ORACLE_TNSv2"

  l4_port_set_entry {
    display_name      = "ORACLE_TNSv2"
    description       = "ORACLE_TNSv2"
    protocol          = "TCP"
    destination_ports = ["1521-1721"]
  }
}
resource "nsxt_policy_service" "SUN_RPC_UDPv2" {
  description  = "SUN_RPC_UDPv2"
  display_name = "SUN_RPC_UDPv2"

  l4_port_set_entry {
    display_name      = "SUN_RPC_UDPv2"
    description       = "SUN_RPC_UDPv2"
    protocol          = "UDP"
    destination_ports = ["111","665-1023"]
  }
}
resource "nsxt_policy_service" "MsAdV2" {
  description  = "Microsoft Active Directory V2"
  display_name = "Microsoft Active Directory V2"

  l4_port_set_entry {
    display_name      = "NBDG-Broadcast-V1"
    description       = "NBDG-Broadcast-V1"
    protocol          = "UDP"
    destination_ports = ["138"]
  }
  l4_port_set_entry {
    display_name      = "LDAP-UDP"
    description       = "LDAP-UDP"
    protocol          = "UDP"
    destination_ports = ["389"]
  }
  l4_port_set_entry {
    display_name      = "Win 2008 - RPC, DCOM, EPM, DRSUAPI, NetLogonR, SamR, FRS"
    description       = "Win 2008 - RPC, DCOM, EPM, DRSUAPI, NetLogonR, SamR, FRS"
    protocol          = "TCP"
    destination_ports = ["49152-65535"]
  }
  l4_port_set_entry {
    display_name      = "Win - RPC, DCOM, EPM, DRSUAPI, NetLogonR, SamR, FRS - UDP"
    description       = "Win - RPC, DCOM, EPM, DRSUAPI, NetLogonR, SamR, FRS - UDP"
    protocol          = "UDP"
    destination_ports = ["1025-65535"]
  }
  l4_port_set_entry {
    display_name      = "Windows-Global-Catalog-over-SSL"
    description       = "Windows-Global-Catalog-over-SSL"
    protocol          = "TCP"
    destination_ports = ["3269"]
  }
  l4_port_set_entry {
    display_name      = "DNS"
    description       = "DNS"
    protocol          = "TCP"
    destination_ports = ["53"]
  }
  l4_port_set_entry {
    display_name      = "Active Directory Server"
    description       = "Active Directory Server"
    protocol          = "TCP"
    destination_ports = ["464"]
  }
  l4_port_set_entry {
    display_name      = "SOAP"
    description       = "SOAP"
    protocol          = "TCP"
    destination_ports = ["9389"]
  }
  l4_port_set_entry {
    display_name      = "Active Directory Server UDP"
    description       = "Active Directory Server UDP"
    protocol          = "UDP"
    destination_ports = ["464"]
  }
  l4_port_set_entry {
    display_name      = "MS-DS-UDP"
    description       = "MS-DS-UDP"
    protocol          = "UDP"
    destination_ports = ["445"]
  }
  l4_port_set_entry {
    display_name      = "NTP Time Server"
    description       = "NTP Time Server"
    protocol          = "UDP"
    destination_ports = ["123"]
  }
  l4_port_set_entry {
    display_name      = "KERBEROS"
    description       = "KERBEROS"
    protocol          = "TCP"
    destination_ports = ["88"]
  }
  l4_port_set_entry {
    display_name      = "Windows-Global-Catalog"
    description       = "Windows-Global-Catalog"
    protocol          = "TCP"
    destination_ports = ["3268"]
  }
  l4_port_set_entry {
    display_name      = "SMTP"
    description       = "SMTP"
    protocol          = "TCP"
    destination_ports = ["25"]
  }
  l4_port_set_entry {
    display_name      = "MS_RPC_TCP"
    description       = "MS_RPC_TCP"
    protocol          = "TCP"
    destination_ports = ["135"]
  }
  l4_port_set_entry {
    display_name      = "WINS"
    description       = "WINS"
    protocol          = "TCP"
    destination_ports = ["42"]
  }
  l4_port_set_entry {
    display_name      = "LDAP-over-SSL"
    description       = "LDAP-over-SSL"
    protocol          = "TCP"
    destination_ports = ["636"]
  }
  l4_port_set_entry {
    display_name      = "Win - RPC, DCOM, EPM, DRSUAPI, NetLogonR, SamR, FRS - TCP"
    description       = "Win - RPC, DCOM, EPM, DRSUAPI, NetLogonR, SamR, FRS - TCP"
    protocol          = "TCP"
    destination_ports = ["1025-65535"]
  }
  l4_port_set_entry {
    display_name      = "KERBEROS-UDP"
    description       = "KERBEROS-UDP"
    protocol          = "UDP"
    destination_ports = ["88"]
  }
  l4_port_set_entry {
    display_name      = "RPC, DFSR (SYSVOL)"
    description       = "RPC, DFSR (SYSVOL)"
    protocol          = "TCP"
    destination_ports = ["5722"]
  }
  l4_port_set_entry {
    display_name      = "DHCP, MADCAP"
    description       = "DHCP, MADCAP"
    protocol          = "UDP"
    destination_ports = ["2535"]
  }
  l4_port_set_entry {
    display_name      = "DNS-UDP"
    description       = "DNS-UDP"
    protocol          = "UDP"
    destination_ports = ["53"]
  }
  l4_port_set_entry {
    display_name      = "WINS-UDP"
    description       = "WINS-UDP"
    protocol          = "UDP"
    destination_ports = ["42"]
  }
  l4_port_set_entry {
    display_name      = "Win 2003 - RPC, DCOM, EPM, DRSUAPI, NetLogonR, SamR, FRS"
    description       = "Win 2003 - RPC, DCOM, EPM, DRSUAPI, NetLogonR, SamR, FRS"
    protocol          = "TCP"
    destination_ports = ["1025-5000"]
  }
  l4_port_set_entry {
    display_name      = "LDAP"
    description       = "LDAP"
    protocol          = "TCP"
    destination_ports = ["389"]
  }
  l4_port_set_entry {
    display_name      = "MS-DS-TCP"
    description       = "MS-DS-TCP"
    protocol          = "TCP"
    destination_ports = ["445"]
  }
  l4_port_set_entry {
    display_name      = "DHCP-Server"
    description       = "DHCP-Server"
    protocol          = "UDP"
    destination_ports = ["67"]
  }
  l4_port_set_entry {
    display_name      = "NBNS-Broadcast-V1"
    description       = "NBNS-Broadcast-V1"
    protocol          = "UDP"
    destination_ports = ["137"]
  }
}