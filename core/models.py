import json

class TargetProfile:
    def __init__(self, ip):
        self.ip = ip
        self.os_family = "desconocido"
        self.os_version = ""
        self.architecture = "x64"
        self.services = []
        self.ports = []
        self.probable_cves = []
        self.attack_surface = []
        self.exploit_candidates = []
        self.nmap_output = ""

    def to_dict(self):
        return {
            "ip": self.ip,
            "os_family": self.os_family,
            "os_version": self.os_version,
            "architecture": self.architecture,
            "services": self.services,
            "ports": self.ports,
            "probable_cves": self.probable_cves,
            "attack_surface": self.attack_surface,
            "exploit_candidates": self.exploit_candidates,
            "nmap_output": self.nmap_output
        }

    @classmethod
    def from_dict(cls, data):
        profile = cls(data.get("ip"))
        profile.os_family = data.get("os_family", "desconocido")
        profile.os_version = data.get("os_version", "")
        profile.architecture = data.get("architecture", "x64")
        profile.services = data.get("services", [])
        profile.ports = data.get("ports", [])
        profile.probable_cves = data.get("probable_cves", [])
        profile.attack_surface = data.get("attack_surface", [])
        profile.exploit_candidates = data.get("exploit_candidates", [])
        profile.nmap_output = data.get("nmap_output", "")
        return profile
