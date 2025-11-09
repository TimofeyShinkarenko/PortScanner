import time
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP, ICMP
from scapy.packet import Raw
from scapy.sendrecv import sr1


class UDPScanner:
    def __init__(self, target_ip, target_ports, guess=None, timeout=2,
                 verbose=False):
        self.target_ip = target_ip
        self.target_ports = target_ports
        self.timeout = timeout
        self.verbose = verbose
        self.guess = guess
        self.echo_payload = b"portscan"

    def create_probe_packet(self, target_port, protocol=None):
        packet = IP(dst=self.target_ip) / UDP(dport=target_port)
        if protocol == "DNS":
            return packet / DNS(id=1, qr=0, opcode=0,
                                qd=DNSQR(qname="google.com"))
        if protocol == "ECHO":
            return packet / self.echo_payload
        return packet

    def scan_port_standard(self, target_port):
        packet = self.create_probe_packet(target_port)
        response = sr1(packet, timeout=self.timeout, verbose=False)

        if response is None:
            return "open|filtered"

        if response.haslayer(ICMP) and response.getlayer(
                ICMP).type == 3 and response.getlayer(ICMP).code == 3:
            return "closed"

        if response.haslayer(UDP):
            return "open"

        return "closed"

    def scan_port_guess(self, target_port):
        protocol_to_guess = self.guess.upper()
        probe_packet = self.create_probe_packet(target_port,
                                                protocol_to_guess)
        response = sr1(probe_packet, timeout=self.timeout, verbose=False)

        if response and response.haslayer(ICMP):
            return "closed", "-"

        if protocol_to_guess == "DNS" and response and response.haslayer(DNS):
            return "open", "DNS"

        if protocol_to_guess == "ECHO" and response and response.haslayer(
                UDP):
            if response.haslayer(Raw) and bytes(
                    response.getlayer(Raw).load) == self.echo_payload:
                return "open", "ECHO"
            return "open", "ECHO?"

        if response is None:
            return "open|filtered", "-"

        return "open", "-"

    def scan_all(self):
        for port in self.target_ports:
            try:
                start_time = time.time()

                protocol = "-"
                if self.guess:
                    status, protocol = self.scan_port_guess(port)
                else:
                    status = self.scan_port_standard(port)

                end_time = time.time()
                duration = end_time - start_time

                if status.startswith("open"):
                    parts = [f"UDP {port}"]
                    if self.verbose:
                        parts.append(f"{int(duration * 1000)} ms")

                    if protocol != "-":
                        parts.append(protocol)

                    yield " ".join(parts)
            except Exception:
                pass
