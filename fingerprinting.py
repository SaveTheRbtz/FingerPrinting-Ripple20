import argparse

import netaddr
from scapy.all import *

import icmp_ms_sync
import ip_ttl_scan
import tcp_fingerprint_scan


def run_tests(address, test_matrix):
    results = []
    for test in test_matrix:
        results.append(test.run(address))
    return results


def main(iface, network, timeout, port):
    # generate test matrix
    test_matrix = []
    test_matrix.append(icmp_ms_sync.Tester(iface, timeout, port))
    test_matrix.append(ip_ttl_scan.Tester(iface, timeout, port))
    test_matrix.append(tcp_fingerprint_scan.Tester(iface, timeout, port))
    # generate table headers
    headers = ["IP"]
    for test in test_matrix:
        headers.append(test.name)

    print("IP\t", "ICMP", "IP TTL", "TCP", sep="\t")
    print("---\t", "---", "---", "---", sep="\t", flush=True)
    net = netaddr.IPNetwork(network)
    for i, ip_dst in enumerate(net):
        # skip
        if ip_dst == net.broadcast:
            continue
        ip_dst = str(ip_dst)
        # for each address, run every test
        test_results = run_tests(ip_dst, test_matrix)
        print(ip_dst, test_results[0], test_results[1], test_results[2], sep="\t", flush=True)


if __name__ == "__main__":
    conf.verb = 0  # make scapy silent

    parser = argparse.ArgumentParser()
    parser.add_argument('network', help="network to scan in CIDR notation (e.g. 10.1.1.0/24)")
    parser.add_argument('-t', '--timeout', type=int, default=0.2, help="packet sniffing timeout (for the response)")
    parser.add_argument('-i', '--iface', default=None, nargs='?',
                        help="interface name as shown in scapy's show_interfaces() function")
    parser.add_argument('-p', '--port', type=int, default=None,
                        help="Specify a port to use for tcp scan instead of common port list")
    args = parser.parse_args()

    iface = args.iface
    if iface is not None and iface.isdigit():
        iface = IFACES.dev_from_index(int(iface)).description

    main(iface, args.network, args.timeout, args.port)
