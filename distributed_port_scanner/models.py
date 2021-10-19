from typing import Optional, List, Callable, Generator

from netaddr import IPAddress, iter_iprange
from pydantic import BaseModel

PortScanCallback = Callable[[IPAddress, int], None]


class IpRange(BaseModel):
    start: IPAddress
    stop: IPAddress


class PortRange(BaseModel):
    start: int
    stop: int


class Ports(BaseModel):
    port_range: Optional[PortRange]
    port_list: Optional[List[int]]

    def __iter__(self) -> Generator[int]:
        if self.port_range and self.port_list:
            raise ValueError("object should contain range/list only")
        if self.port_range:
            yield from range(self.port_range.start, self.port_range.stop)
        elif self.port_list:
            yield from self.port_list


class IPAddresses(BaseModel):
    ip_range: Optional[IpRange]
    ip_list: Optional[List[IPAddress]]

    def __iter__(self):
        return self.hosts()

    def hosts(self):
        if self.ip_range and self.ip_list:
            raise ValueError("object should contain range/list only")
        if self.ip_range:
            yield from iter_iprange(self.ip_range.start, self.ip_range.stop)
        elif self.ip_list:
            yield from self.ip_list


class PortsReport(BaseModel):
    ip_address: IPAddress
    ports: List[int]


class Scan(BaseModel):
    scan_timestamp: int
    addresses: IPAddresses
    open_ports: List[PortsReport]
    failure_ports: List[PortsReport]


class ScanTask(BaseModel):
    target: IPAddress
    ports: Ports
