import socket
import ipaddress

# Cisco Umbrella block page IP addresses (A and AAAA)
BLOCK_IPS = {
    "146.112.61.104",
    "146.112.61.105",
    "146.112.61.106",
    "146.112.61.107",
    "146.112.61.108",
    "146.112.61.110",
    "::ffff:146.112.61.104",
    "::ffff:146.112.61.105",
    "::ffff:146.112.61.106",
    "::ffff:146.112.61.107",
    "::ffff:146.112.61.108",
    "::ffff:146.112.61.110"
}

def is_umbrella_blocked(domain):
    """
    Resolves a domain and returns True if the response matches a Cisco Umbrella block page,
    otherwise returns False.
    """
    try:
        infos = socket.getaddrinfo(domain, None)
        for info in infos:
            family, _, _, _, sockaddr = info
            if family == socket.AF_INET:
                ip = sockaddr[0]
            elif family == socket.AF_INET6:
                ip = ipaddress.ip_address(sockaddr[0]).compressed
            else:
                continue
            try:
                ip_obj = ipaddress.ip_address(ip)
                if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
                    ip = f"::ffff:{ip_obj.ipv4_mapped}"
            except Exception:
                pass
            if ip in BLOCK_IPS:
                return True
        return False
    except Exception:
        # If resolution fails, consider it not blocked by Umbrella
        return False

# Example usage
if __name__ == "__main__":
    domain = "internetbadguys.com"
    result = is_umbrella_blocked(domain)
    print(f"Domain {domain} is blocked by Umbrella: {result}")