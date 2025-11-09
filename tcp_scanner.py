import time
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import sr1, send


class TCPScanner:
    def __init__(self, target_ip, target_ports, timeout=2,
                 verbose=False, guess=None):
        self.target_ip = target_ip
        self.target_ports = target_ports
        self.timeout = timeout
        self.verbose = verbose
        self.guess = guess
        self.guessers = {
            "HTTP": self.guess_http,
            "ECHO": self.guess_echo,
        }

    def create_packet(self, target_port, flags):
        return IP(dst=self.target_ip) / TCP(dport=target_port,
                                            flags=flags)

    def send_rst(self, target_port, response):
        rst_packet = IP(dst=self.target_ip) / TCP(
            dport=target_port,
            sport=response[TCP].dport,
            flags="R",
            seq=response[TCP].ack
        )
        send(rst_packet, verbose=False)

    def analyze_syn_scan_response(self, response, target_port):
        if response is None:
            return "filtered"
        if response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)

            if tcp_layer.flags == 0x12:
                self.send_rst(target_port, response)
                return "open"

            elif tcp_layer.flags == 0x14:
                return "closed"

        return "filtered"

    def guess_http(self, target_port):
        session_details = None
        try:
            syn_packet = self.create_packet(target_port, 'S')
            syn_ack_response = sr1(syn_packet, timeout=self.timeout,
                                   verbose=False)

            if not (syn_ack_response and syn_ack_response.haslayer(
                    TCP) and syn_ack_response.getlayer(TCP).flags == 0x12):
                return "-"

            http_get_request = b'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' % self.target_ip.encode()
            request_packet = IP(dst=self.target_ip) / TCP(
                sport=syn_ack_response[TCP].dport,
                dport=target_port,
                flags="PA",
                seq=syn_ack_response.ack,
                ack=syn_ack_response.seq + 1
            ) / http_get_request

            http_response = sr1(request_packet, timeout=self.timeout,
                                verbose=False)

            if http_response:
                session_details = (
                    http_response[TCP].dport, http_response.ack)
            else:
                session_details = (request_packet.sport,
                                   request_packet.seq + len(http_get_request))

            if http_response and http_response.haslayer(Raw):
                payload = bytes(http_response.getlayer(Raw).load)
                if b'HTTP' in payload:
                    return "HTTP"

        except Exception:
            pass

        finally:
            if session_details:
                sport, seq = session_details
                rst_packet = IP(dst=self.target_ip) / TCP(sport=sport,
                                                          dport=target_port,
                                                          flags="R", seq=seq)
                send(rst_packet, verbose=False)

        return "-"

    def guess_echo(self, target_port):
        session_details = None
        try:
            syn_packet = self.create_packet(target_port, 'S')
            syn_ack_response = sr1(syn_packet, timeout=self.timeout,
                                   verbose=False)

            if not (syn_ack_response and syn_ack_response.haslayer(
                    TCP) and syn_ack_response.getlayer(TCP).flags == 0x12):
                return "-"

            payload = b"Hello, Echo!"
            request_packet = IP(dst=self.target_ip) / TCP(
                sport=syn_ack_response[TCP].dport,
                dport=target_port,
                flags="PA",
                seq=syn_ack_response.ack,
                ack=syn_ack_response.seq + 1
            ) / payload

            echo_response = sr1(request_packet, timeout=self.timeout,
                                verbose=False)

            if echo_response:
                session_details = (
                    echo_response[TCP].dport, echo_response.ack)
            else:
                session_details = (
                    request_packet.sport, request_packet.seq + len(payload))

            if echo_response and echo_response.haslayer(Raw):
                if bytes(echo_response[Raw].load) == payload:
                    return "ECHO"

        except Exception:
            pass

        finally:
            if session_details:
                sport, seq = session_details
                rst_packet = IP(dst=self.target_ip) / TCP(sport=sport,
                                                          dport=target_port,
                                                          flags="R", seq=seq)
                send(rst_packet, verbose=False)

        return "-"

    def scan_port(self, target_port):
        syn_packet = self.create_packet(target_port, flags="S")
        try:
            start_time = time.time()
            response = sr1(syn_packet, timeout=self.timeout, verbose=False)
            end_time = time.time()

            return (self.analyze_syn_scan_response(response, target_port),
                    end_time - start_time)

        except Exception:
            return "error", 0

    def scan_all(self):
        for port in self.target_ports:
            status, duration = self.scan_port(port)

            if status == "open":
                parts = [f"TCP {port}"]
                if self.verbose:
                    parts.append(f"{int(duration * 1000)} ms")

                if self.guess:
                    guess_func = self.guessers.get(self.guess.upper())
                    protocol = guess_func(port) if guess_func else "-"
                    parts.append(protocol)

                yield " ".join(parts)
