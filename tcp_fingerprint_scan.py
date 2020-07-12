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
DEFAULT_MSS = 69
# set to True in networks where routers/firewalls unconditionally modify MSS
IGNORE_MSS = False


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
            syn = IP(dst=address) / TCP(
                sport=sport,
                dport=port,
                flags="S",
                seq=1000,
                options=[
                    ("WScale", 7),
                    ("MSS", DEFAULT_MSS),
                    ("SAckOK", b""),
                    ("Timestamp", (0, 0)),
                ],
            )
            synack = sr1(syn, timeout=self.timeout)

            # no response
            if not synack:
                continue

            # check if we really got a SYN-ACK
            if not synack.haslayer("TCP") or synack.sprintf("%TCP.flags%") != "SA":
                continue

            matched_mss, matched_wscale, matched_ts = False, False, False
            for option in synack["TCP"].options:
                opt_name, opt_value = option[0], option[1]
                if opt_name == "WScale":
                    if opt_value == 0:
                        matched_wscale = True
                    else:
                        break
                elif opt_name == "MSS":
                    if opt_value == DEFAULT_MSS or IGNORE_MSS:
                        matched_mss = True
                    else:
                        break
                elif opt_name == "Timestamp":
                    matched_ts = True
            if matched_mss and matched_wscale and matched_ts:
                return PASS_STR
            return FAIL_STR

        return N_A_STR
