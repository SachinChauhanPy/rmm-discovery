from scapy.all import ARP, Ether, srp
import socket
import logging

logger = logging.getLogger(__name__)

def arp_scan(ip):
    """Perform ARP scan to discover devices."""
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered, _ = srp(arp_request_broadcast, timeout=2, verbose=False)
        
        for sent, received in answered:
            logger.debug(f"ARP Response from {received.psrc} with MAC {received.hwsrc}")
            return {"ip": received.psrc, "mac": received.hwsrc}
    except Exception as e:
        logger.error(f"Error during ARP scan for {ip}: {e}")
    return None

def get_hostname(ip):
    """Retrieve the hostname using reverse DNS lookup."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        logger.debug(f"Hostname for {ip}: {hostname}")
        return hostname
    except socket.herror:
        logger.debug(f"No hostname found for {ip}")
        return None
