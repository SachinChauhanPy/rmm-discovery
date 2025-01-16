from dataclasses import dataclass

@dataclass
class DeviceInfo:
    ip: str
    mac: str
    hostname: str
