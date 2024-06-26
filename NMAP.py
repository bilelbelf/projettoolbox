import nmap

def scan_ports(ip, port_range):
    nm = nmap.PortScanner()
    nm.scan(ip, port_range)
    results = []
    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in lport:
            results.append((port, nm[ip][proto][port]['name'], nm[ip][proto][port]['state']))
    return results
