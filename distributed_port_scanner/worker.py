import socket

from distributed_port_scanner.models import IPAddress, Ports, PortScanCallback


def scan_ip(target: IPAddress, ports: Ports, open_callback: PortScanCallback, failure_callback: PortScanCallback):
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)

            # returns an error indicator
            result = s.connect_ex((str(target), port))
            if result == 0:
                open_callback(target, port)
            s.close()

        except socket.gaierror:
            failure_callback(target, port)
        except socket.error:
            failure_callback(target, port)
