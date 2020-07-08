"""
Name: TCP Fingerprint Scanner
Description: Checks for special TCP properties
"""
import random

from scapy.all import IP, TCP, sr1

PASS_STR = "PASS"
FAIL_STR = "FAIL"
N_A_STR = "N/A"

COMMON_OPEN_PORTS = [443, 80, 21, 23, 22, 25, 465, 587, 161, 53]
DEFAULT_MSS = 1280

class Tester:
    name = "UNIQUE TCP"

    def __init__(self, iface, timeout, port):
        self.iface = iface
        self.timeout = timeout
        self.port = port

    def run(self, address):
        """
        Run the test.
        Should return True or False.
        """
        # Run in a loop over a list of possible ports..
        if self.port:
            use_ports = [self.port] if type(self.port) == int else self.port
        else:
            use_ports = COMMON_OPEN_PORTS

        for port in use_ports:
            # send SYN
            sport = random.randint(1024, 65535)
            syn = IP(dst=address) / TCP(sport=sport, dport=port, flags='S', seq=1000,
                                        options=[("WScale", 123), ("MSS", DEFAULT_MSS)])
            synack = sr1(syn, timeout=self.timeout)

            # no response
            if not synack:
                continue

            # check if we really got a SYN-ACK
            if not synack.haslayer("TCP") or synack["TCP"].flags != "SA":
                continue

            matched_mss, matched_wscale = False, False
            for option in synack["TCP"].options:
                if option[0] == 'WScale':
                    # check if we got zero
                    if option[1] == 0:
                        matched_wscale = True
                    else:
                        break
                if option[0] == 'MSS':
                    # check if we got zero
                    if option[1] == DEFAULT_MSS:
                        matched_mss = True
                    else:
                        break
            if matched_mss and matched_wscale:
                return PASS_STR
            return FAIL_STR

        return N_A_STR
