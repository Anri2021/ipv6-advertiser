from __future__ import annotations

import ctypes
import json
import ipaddress
import logging
import logging.handlers
import os
import queue
import random
import signal
import socket
import struct
import sys
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from scapy.config import conf
from scapy.layers.inet6 import (
    ICMPv6ND_NS,
    ICMPv6ND_RA,
    ICMPv6ND_RS,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptRDNSS,
    ICMPv6NDOptSrcLLAddr,
    IPv6,
    in6_chksum,
)

from scapy.layers.dhcp import BOOTP
from scapy.layers.l2 import ARP,Ether
from scapy.sendrecv import AsyncSniffer
from scapy.utils import checksum


ND_MIN_LENGTH = {133: 8, 134: 16, 135: 24}
ND_TYPES = {133: ICMPv6ND_RS, 134: ICMPv6ND_RA, 135: ICMPv6ND_NS}

ND_DIAGNOSTIC_LOG_INTERVAL = 5.0
PRESENCE_COOLDOWN = 30.0

# ============================================================
# 1. Configuration
# ============================================================

# מומלץ להגדיר מזהה יציב אחד בלבד.
# סדר העדיפות המומלץ:
# GUID -> שם קבוע -> MAC -> Interface Index.
#
# אם לא הוגדר משתנה סביבה אחר, ברירת המחדל היא
# מתאם Windows ששמו המדויק "Wi-Fi".

# טעינת קובץ תצורה אופציונלי בעל אותו שם של הסקריפט (.conf או .json)
def _resolve_config_path() -> Path:
    for idx, arg in enumerate(sys.argv[:-1]):
        if arg.lower() in ("-c", "--conf", "-conf","--config", "-config", "-configfile", "--configfile"):
            return Path(sys.argv[idx + 1]).resolve()
    env_path = os.getenv("RA_CONFIG_PATH")
    if env_path:
        return Path(env_path).resolve()
    return Path(__file__).resolve().with_suffix(".conf")

_CONFIG_PATH = _resolve_config_path()

_FILE_CONFIG: dict = {}

if _CONFIG_PATH.is_file():
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as _f:
            _FILE_CONFIG = json.load(_f)
    except Exception as _exc:
        print(f"Warning: Could not read config file {_CONFIG_PATH}: {_exc}", file=sys.stderr)


def _get_setting(env_name: str, conf_key: str, default=None):
    """מדרג עדיפויות: 1. משתנה סביבה -> 2. קובץ קונפיגורציה מקונן (Dot Notation) -> 3. ערך ברירת מחדל"""
    val = os.getenv(env_name)
    if val is not None and val != "":
        return val
    
    curr = _FILE_CONFIG
    found = True
    for part in conf_key.split("."):
        if isinstance(curr, dict) and part in curr:
            curr = curr[part]
        else:
            found = False
            break
    
    if found and curr is not None:
        return curr
    return default


# הגדרת בורר המתאם מתוך מבנה ה-Interface בקונפיגורציה
INTERFACE_GUID = _get_setting("RA_INTERFACE_GUID", "Interface.Guid")
INTERFACE_MAC = _get_setting("RA_INTERFACE_MAC", "Interface.Mac")

_raw_index = _get_setting("RA_INTERFACE_INDEX", "Interface.Index")
INTERFACE_INDEX = int(_raw_index) if _raw_index not in (None, "") else None

_raw_name = _get_setting("RA_INTERFACE_NAME", "Interface.Name")
if _raw_name is not None:
    INTERFACE_NAME = _raw_name or None
elif INTERFACE_GUID is None and INTERFACE_MAC is None and INTERFACE_INDEX is None:
    INTERFACE_NAME = "Wi-Fi"
else:
    INTERFACE_NAME = None

# הגדרות רשת מתוך מבנה ה-Network בקונפיגורציה
ULA_PREFIX = _get_setting("RA_ULA_PREFIX", "Network.UlaPrefix", "fd10:100:104::/64")
LOCAL_DNS = _get_setting("RA_LOCAL_DNS", "Network.LocalDns", "fd10:100:104::3")
SECONDARY_DNS = _get_setting("RA_SECONDARY_DNS", "Network.SecondaryDns", "2001:4860:4860::8888")

# דיאגנוסטיקה מתוך מבנה ה-Diagnostics בקונפיגורציה
_nd_chk = _get_setting("RA_ND_CHECKSUM_DIAGNOSTICS", "Diagnostics.NdChecksum", False)
ND_CHECKSUM_DIAGNOSTICS = bool(_nd_chk) if isinstance(_nd_chk, bool) else str(_nd_chk).lower() in ("1", "true")

DEFAULT_LOG_PATH = (
    Path(os.getenv("PROGRAMDATA", str(Path.home())))
    / "RaEngine"
    / "logs"
    / "ra-engine.log"
)

_log_path_val = _get_setting("RA_LOG_PATH", "Diagnostics.LogPath")
LOG_PATH = Path(_log_path_val) if _log_path_val else DEFAULT_LOG_PATH

# RFC 4861 / RFC 8106
MIN_DELAY_BETWEEN_RAS = 3.0
MAX_RA_DELAY_TIME = 0.5

MIN_PERIODIC_INTERVAL = 400.0
MAX_PERIODIC_INTERVAL = 600.0

PREFIX_VALID_LIFETIME = 86_400
PREFIX_PREFERRED_LIFETIME = 14_400

# RFC 8106 section 5.1 recommends at least 3 * MaxRtrAdvInterval.
RDNSS_LIFETIME = 1_800

INITIAL_RA_COUNT = 3
INITIAL_RA_INTERVAL = 3.2

ULA_RETRY_DELAY = 3.5
ULA_CONFIRMATION_TTL = 60.0

RS_PER_DEVICE_COOLDOWN = 1.0
PRIMARY_RA_FOLLOWUP_COOLDOWN = 30.0

SEND_FAILURE_RETRY_DELAY = 3.1
MAX_SEND_ATTEMPTS = 2

INTERFACE_POLL_INTERVAL = 5.0
SNIFFER_STOP_TIMEOUT = 2.0
LOG_QUEUE_CAPACITY = 4096


# מגבלות למניעת הצטברות state בלתי מוגבלת.
MAX_TRACKED_DEVICES = 2_048
MAX_PENDING_DESTINATIONS = 256
MAX_REASONS_PER_REQUEST = 8


LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 5


GUA_NET: Final = ipaddress.IPv6Network("2000::/3")

ULA_NET: Final = ipaddress.IPv6Network(ULA_PREFIX)

LOCAL_DNS_ADDR: Final = ipaddress.IPv6Address(LOCAL_DNS)

SECONDARY_DNS_ADDR: Final = ipaddress.IPv6Address(SECONDARY_DNS)

# ============================================================
# 2. Runtime Models
# ============================================================

@dataclass(frozen=True, slots=True)
class InterfaceBinding:
    iface: object
    index: int
    ipv6_index: int
    name: str
    description: str
    guid: str
    mac: str
    link_local: str
    generation: int

    @property
    def identity(self) -> tuple[int, int, str, str, str]:
        return (self.index,self.ipv6_index, self.guid, self.mac, self.link_local)


@dataclass(frozen=True, slots=True)
class Destination:
    ipv6: str
    mac: str
    multicast: bool


MULTICAST_DESTINATION: Final = Destination(
    ipv6="ff02::1", mac="33:33:00:00:00:01", multicast=True
)


@dataclass(slots=True)
class PendingTransmission:
    deadline: float
    reasons: set[str] = field(default_factory=set)


class InterfaceUnavailable(RuntimeError):
    pass


class InterfaceQueryError(RuntimeError):
    pass


# ============================================================
# 3. Validation and Logging
# ============================================================


def validate_configuration() -> None:
    selectors = [
        INTERFACE_GUID is not None,
        INTERFACE_NAME is not None,
        INTERFACE_MAC is not None,
        INTERFACE_INDEX is not None,
    ]

    if sum(selectors) != 1:
        raise RuntimeError(
            "Configure exactly one interface selector: "
            "GUID, name, MAC or index. "
            "When using an environment selector, set "
            "RA_INTERFACE_NAME to an empty value if the "
            "default Wi-Fi name must be disabled."
        )

    if ULA_NET.prefixlen != 64:
        raise RuntimeError("SLAAC with the A flag requires a /64 prefix")

    if LOCAL_DNS_ADDR not in ULA_NET:
        raise RuntimeError(f"LOCAL_DNS {LOCAL_DNS} is outside {ULA_PREFIX}")

    if PREFIX_PREFERRED_LIFETIME > PREFIX_VALID_LIFETIME:
        raise RuntimeError("Preferred lifetime cannot exceed valid lifetime")

    if not 0 <= RDNSS_LIFETIME <= 0xFFFFFFFF:
        raise RuntimeError("RDNSS lifetime must fit an unsigned 32-bit value")


class BoundedQueueHandler(logging.handlers.QueueHandler):
    """Drop newest records on overload; Handler's lock protects the counter."""

    def __init__(self, log_queue):
        super().__init__(log_queue)
        self.dropped = 0
        self.accepting = True

    def enqueue(self, record):
        if not self.accepting:
            return
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            self.dropped += 1

    def stop_accepting(self):
        self.acquire()
        try:
            self.accepting = False
        finally:
            self.release()


class BoundedQueueListener(logging.handlers.QueueListener):
    """Make room for the shutdown sentinel even after a log burst."""

    def enqueue_sentinel(self):
        while True:
            try:
                self.queue.put_nowait(self._sentinel)
                return
            except queue.Full:
                try:
                    self.queue.get_nowait()
                    self.queue.task_done()
                except queue.Empty:
                    pass


def configure_logging() -> tuple[logging.Logger, logging.handlers.QueueListener]:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(threadName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler()
    console.setFormatter(formatter)

    rotating_file = logging.handlers.RotatingFileHandler(
        LOG_PATH, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8"
    )

    rotating_file.setFormatter(formatter)

    log_queue = queue.Queue(maxsize=LOG_QUEUE_CAPACITY)
    queue_handler = BoundedQueueHandler(log_queue)

    logger = logging.getLogger("ra-engine")

    logger.handlers.clear()
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(queue_handler)

    listener = BoundedQueueListener(
        log_queue, console, rotating_file, respect_handler_level=True
    )

    listener.start()

    return logger, listener


def is_elevated_windows_process() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def normalize_mac(value: str | None) -> str:
    if not value:
        return ""

    hexadecimal = "".join(
        character for character in value.lower() if character in "0123456789abcdef"
    )

    if len(hexadecimal) != 12:
        return ""

    return ":".join(hexadecimal[index : index + 2] for index in range(0, 12, 2))


def is_unicast_mac(value: str) -> bool:
    normalized = normalize_mac(value)

    if not normalized or normalized == "00:00:00:00:00:00":
        return False

    return (int(normalized[0:2], 16) & 1) == 0


def normalized_guid(value: str | None) -> str:
    return (value or "").strip().strip("{}").lower()


# ============================================================
# 4. Windows Interface Resolution
# ============================================================


class WindowsAdapterQuery:
    """Reuse Scapy's ABI definitions; own the buffer until all pointers are read.

    Scapy 2.7.0 is pinned because its Windows structures are version-specific.
    No PowerShell, JSON, WMI, copied Windows structures or pointer escape.
    Only the interface-monitor thread calls this object.
    """

    def __init__(self):
        from ctypes import wintypes

        from scapy.arch.windows.structures import IP_ADAPTER_ADDRESSES

        self.address_type = IP_ADAPTER_ADDRESSES
        self.ulong = wintypes.ULONG
        self.api = ctypes.WinDLL("iphlpapi", use_last_error=True).GetAdaptersAddresses
        self.api.argtypes = [
            wintypes.ULONG,
            wintypes.ULONG,
            ctypes.c_void_p,
            ctypes.POINTER(IP_ADAPTER_ADDRESSES),
            ctypes.POINTER(wintypes.ULONG),
        ]
        self.api.restype = wintypes.ULONG
        self.buffer = ctypes.create_string_buffer(15 * 1024)

    def __call__(self):
        # Skip anycast, multicast and DNS lists; include interfaces without IPs.
        flags = 0x0002 | 0x0004 | 0x0008 | 0x0100
        for _ in range(3):
            size = self.ulong(len(self.buffer))
            head = ctypes.cast(self.buffer, ctypes.POINTER(self.address_type))
            status = self.api(socket.AF_UNSPEC, flags, None, head, ctypes.byref(size))
            if status == 232:  # ERROR_NO_DATA
                return []
            if status == 111:  # ERROR_BUFFER_OVERFLOW during an adapter change
                if not 0 < size.value <= 1024 * 1024:
                    raise InterfaceQueryError("Adapter buffer exceeds 1 MiB limit")
                self.buffer = ctypes.create_string_buffer(size.value)
                continue
            if status:
                raise InterfaceQueryError(f"GetAdaptersAddresses failed: {status}")
            return self._read_adapters(head)
        raise InterfaceQueryError("Adapter table changed repeatedly; retry next poll")

    @staticmethod
    def _read_adapters(head):
        result = []
        current = head
        while current:
            item = current.contents
            addresses = []
            unicast = item.first_unicast_address
            while unicast:
                entry = unicast.contents
                address = entry.address.address
                if entry.dad_state == 4 and address:  # IpDadStatePreferred
                    sockaddr = address.contents
                    if sockaddr.si_family == socket.AF_INET6:
                        packed = bytes(sockaddr.Ipv6.sin6_addr.byte)
                        ip = ipaddress.IPv6Address(packed)
                        if ip.is_link_local:
                            addresses.append(str(ip))
                unicast = entry.next
            mac = (
                bytes(x & 0xFF for x in item.physical_address[:6]).hex(":")
                if item.physical_address_length == 6
                else ""
            )
            result.append(
                {
                    "Name": item.friendly_name or "",
                    "Description": item.description or "",
                    "InterfaceGuid": (item.adapter_name or b"").decode("ascii"),
                    "InterfaceIndex": item.interface_index or item.ipv6_interface_index,
                    "IPv6InterfaceIndex": item.ipv6_interface_index or item.interface_index,
                    "MacAddress": mac,
                    "Status": "Up" if item.oper_status == 1 else "Down",
                    "LinkLocal": addresses,
                }
            )
            current = item.next
        return result


_adapter_query = None


def query_windows_adapters() -> list[dict[str, object]]:
    global _adapter_query
    try:
        if _adapter_query is None:
            _adapter_query = WindowsAdapterQuery()
        return _adapter_query()
    except InterfaceQueryError:
        raise
    except Exception as exc:
        raise InterfaceQueryError(f"Could not query Windows adapters: {exc}") from exc


def adapter_matches(adapter: dict[str, object]) -> bool:
    if INTERFACE_GUID is not None:
        return normalized_guid(
            str(adapter.get("InterfaceGuid", ""))
        ) == normalized_guid(INTERFACE_GUID)

    if INTERFACE_NAME is not None:
        return str(adapter.get("Name", "")).casefold() == (INTERFACE_NAME.casefold())

    if INTERFACE_MAC is not None:
        return normalize_mac(str(adapter.get("MacAddress", ""))) == normalize_mac(
            INTERFACE_MAC
        )

    return int(adapter.get("InterfaceIndex", -1)) == INTERFACE_INDEX


def resolve_interface(next_generation: int) -> InterfaceBinding:
    matches = [item for item in query_windows_adapters() if adapter_matches(item)]

    if not matches:
        raise InterfaceUnavailable("The configured network adapter was not found")

    if len(matches) > 1:
        raise InterfaceUnavailable("The configured interface selector is ambiguous")

    adapter = matches[0]

    if str(adapter.get("Status", "")).casefold() != "up":
        raise InterfaceUnavailable(
            f"Adapter {adapter.get('Name', '<unknown>')} is not Up"
        )

    index = int(adapter["InterfaceIndex"])

    mac = normalize_mac(str(adapter.get("MacAddress", "")))

    if not is_unicast_mac(mac):
        raise InterfaceUnavailable("The selected adapter has no usable unicast MAC")

    raw_addresses = adapter.get("LinkLocal", [])

    if isinstance(raw_addresses, str):
        raw_addresses = [raw_addresses]

    link_local_addresses: list[ipaddress.IPv6Address] = []

    if isinstance(raw_addresses, list):
        for raw_address in raw_addresses:
            try:
                address = ipaddress.IPv6Address(str(raw_address).split("%", 1)[0])
            except ValueError:
                continue

            if address.is_link_local:
                link_local_addresses.append(address)

    if not link_local_addresses:
        raise InterfaceUnavailable(
            "The selected adapter has no preferred Link-Local IPv6 address"
        )

    guid = normalized_guid(str(adapter.get("InterfaceGuid", "")))
    if not guid:
        raise InterfaceUnavailable("Adapter has no Npcap-compatible GUID")
    scapy_iface = r"\Device\NPF_" + "{" + guid.upper() + "}"

    return InterfaceBinding(
        iface=scapy_iface,
        index=index,
        ipv6_index=int(adapter["IPv6InterfaceIndex"]),
        name=str(adapter.get("Name", "")),
        description=str(adapter.get("Description", "")),
        guid=normalized_guid(str(adapter.get("InterfaceGuid", ""))),
        mac=mac,
        link_local=str(min(link_local_addresses, key=int)),
        generation=next_generation,
    )


# ============================================================
# 5. Router Advertisement Engine
# ============================================================


class RouterAdvertisementEngine:
    def __init__(self, logger: logging.Logger) -> None:
        self.log = logger

        self.stop_event = threading.Event()
        self.failure_event = threading.Event()

        self.monitor_wakeup = threading.Event()

        self.stop_lock = threading.Lock()

        self.stopped = False

        self.binding_lock = threading.RLock()

        self.binding: InterfaceBinding | None = None

        self.generation = 0

        self.condition = threading.Condition(threading.RLock())

        self.pending: dict[Destination, PendingTransmission] = {}

        self.last_multicast_sent_timestamp = 0.0
        self.last_checksum_diagnostic = 0.0
        self.send_in_progress = False
        self._send_socket = None
        self._send_generation = -1
        self._multicast_frame = None

        self.initial_ra_remaining = 0
        self.periodic_enabled = False

        self.next_periodic_deadline: float | None = None

        self.confirmed_ula_devices: OrderedDict[str, float] = OrderedDict()

        self.pending_ula_retries: OrderedDict[str, float] = OrderedDict()
        
        self.last_presence_by_mac: OrderedDict[str, float] = OrderedDict()

        self.last_rs_by_mac: OrderedDict[str, float] = OrderedDict()

        self.last_primary_ra: OrderedDict[str, float] = OrderedDict()

        self.threads: list[threading.Thread] = []

    # --------------------------------------------------------
    # Interface lifecycle
    # --------------------------------------------------------

    def binding_snapshot(self) -> InterfaceBinding | None:
        with self.binding_lock:
            return self.binding

    def install_binding(self, candidate: InterfaceBinding) -> bool:
        with self.condition:
            with self.binding_lock:
                old = self.binding

                if old is not None and old.identity == candidate.identity:
                    return False

                self.generation += 1

                candidate = InterfaceBinding(
                    iface=candidate.iface,
                    index=candidate.index,
                    ipv6_index=candidate.ipv6_index,
                    name=candidate.name,
                    description=(candidate.description),
                    guid=candidate.guid,
                    mac=candidate.mac,
                    link_local=(candidate.link_local),
                    generation=(self.generation),
                )

                self.binding = candidate

            with self.condition:
                self._reset_runtime_state_locked()

                self.initial_ra_remaining = INITIAL_RA_COUNT

                self._enqueue_locked(
                    MULTICAST_DESTINATION,
                    time.monotonic(),
                    f"Initial RA 1/{INITIAL_RA_COUNT}",
                )

                self.condition.notify_all()

            self.log.info(
                "Bound adapter name=%s "
                "description=%s index=%d "
                "guid=%s mac=%s "
                "link_local=%s",
                candidate.name,
                candidate.description,
                candidate.index,
                candidate.guid,
                candidate.mac,
                candidate.link_local,
            )

            return True

    def invalidate_binding(self, generation: int, reason: str) -> None:
        with self.condition:
            with self.binding_lock:
                current = self.binding

                if current is None or current.generation != generation:
                    return

                self.binding = None
                self.generation += 1

            with self.condition:
                self._reset_runtime_state_locked()
                self.condition.notify_all()

            self.log.warning("Adapter binding invalidated: %s", reason)

            self.monitor_wakeup.set()

    def _reset_runtime_state_locked(self) -> None:
        self.pending.clear()
        self.confirmed_ula_devices.clear()
        self.pending_ula_retries.clear()
        self.last_rs_by_mac.clear()
        self.last_primary_ra.clear()
        self.last_presence_by_mac.clear()

        self.last_multicast_sent_timestamp = 0.0
        self.initial_ra_remaining = 0
        self.periodic_enabled = False
        self.next_periodic_deadline = None

    def interface_monitor_worker(self) -> None:
        last_status = ""

        while not self.stop_event.is_set():
            try:
                with self.binding_lock:
                    next_generation = self.generation + 1

                candidate = resolve_interface(next_generation)

                self.install_binding(candidate)

                last_status = "ready"

            except InterfaceUnavailable as exc:
                current = self.binding_snapshot()

                if current is not None:
                    self.invalidate_binding(current.generation, str(exc))

                if last_status != str(exc):
                    self.log.warning("Waiting for configured adapter: %s", exc)

                    last_status = str(exc)

            except InterfaceQueryError as exc:
                # כשל שאילתת Windows רגעי אינו מבטל
                # לכידה תקינה שכבר פועלת.
                if last_status != str(exc):
                    self.log.error("Adapter health query failed: %s", exc)

                    last_status = str(exc)

            except Exception:
                self.log.exception("Unexpected interface monitor failure")

            self.monitor_wakeup.wait(INTERFACE_POLL_INTERVAL)

            self.monitor_wakeup.clear()

    # --------------------------------------------------------
    # Bounded device state
    # --------------------------------------------------------

    @staticmethod
    def _bounded_set(
        values: set[str], value: str, maximum: int = (MAX_REASONS_PER_REQUEST)
    ) -> None:
        if len(values) < maximum:
            values.add(value)

    @staticmethod
    def _join_all_routers_group(interface_index: int):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        membership = socket.inet_pton(socket.AF_INET6, "ff02::2") + struct.pack("@I", interface_index)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, membership)
        return sock

    @staticmethod
    def _put_bounded(values: OrderedDict[str, float], key: str, value: float) -> None:
        values.pop(key, None)

        values[key] = value

        while len(values) > MAX_TRACKED_DEVICES:
            values.popitem(last=False)

    def _cleanup_device_state_locked(self, now: float) -> None:
        collections = (
            (self.confirmed_ula_devices, ULA_CONFIRMATION_TTL),
            (self.last_rs_by_mac, max(ULA_CONFIRMATION_TTL, RS_PER_DEVICE_COOLDOWN)),
            (
                self.last_primary_ra,
                max(ULA_CONFIRMATION_TTL, PRIMARY_RA_FOLLOWUP_COOLDOWN),
            ),
            (self.last_presence_by_mac, PRESENCE_COOLDOWN),
        )

        for values, ttl in collections:
            while values:
                _, timestamp = next(iter(values.items()))

                if now - timestamp < ttl:
                    break

                values.popitem(last=False)

    def was_ula_recently_confirmed(self, device_mac: str) -> bool:
        now = time.monotonic()

        with self.condition:
            self._cleanup_device_state_locked(now)

            confirmed_at = self.confirmed_ula_devices.get(device_mac)

            return (
                confirmed_at is not None and now - confirmed_at < ULA_CONFIRMATION_TTL
            )

    def confirm_ula_device(self, device_mac: str) -> None:
        now = time.monotonic()

        with self.condition:
            self._cleanup_device_state_locked(now)

            self._put_bounded(self.confirmed_ula_devices, device_mac, now)

            self.pending_ula_retries.pop(device_mac, None)

            self.condition.notify_all()

    def reset_device_state(self, device_mac: str) -> None:
        with self.condition:
            self.confirmed_ula_devices.pop(device_mac, None)

            self.pending_ula_retries.pop(device_mac, None)

            self.last_rs_by_mac.pop(device_mac, None)

            self.condition.notify_all()

    def permit_rs(self, device_mac: str) -> bool:
        now = time.monotonic()

        with self.condition:
            self._cleanup_device_state_locked(now)

            previous = self.last_rs_by_mac.get(device_mac)

            if previous is not None and now - previous < RS_PER_DEVICE_COOLDOWN:
                return False

            self._put_bounded(self.last_rs_by_mac, device_mac, now)

            return True

    def permit_primary_ra_followup(self, source: str) -> bool:
        now = time.monotonic()

        with self.condition:
            self._cleanup_device_state_locked(now)

            previous = self.last_primary_ra.get(source)

            if previous is not None and now - previous < PRIMARY_RA_FOLLOWUP_COOLDOWN:
                return False

            self._put_bounded(self.last_primary_ra, source, now)

            return True

    # --------------------------------------------------------
    # Scheduler
    # --------------------------------------------------------

    def _enqueue_locked(
        self, destination: Destination, deadline: float, reason: str
    ) -> None:
        # Multicast ממתין כבר מגיע לכל המכשירים,
        # ולכן ניתן לאחד לתוכו בקשות Unicast.
        multicast_pending = self.pending.get(MULTICAST_DESTINATION)

        if multicast_pending is not None:
            multicast_pending.deadline = min(multicast_pending.deadline, deadline)

            self._bounded_set(multicast_pending.reasons, reason)

            return

        if destination.multicast:
            merged_reasons = {reason}

            for pending in self.pending.values():
                for old_reason in pending.reasons:
                    self._bounded_set(merged_reasons, old_reason)

            self.pending.clear()

            self.pending[destination] = PendingTransmission(deadline, merged_reasons)

            return

        existing = self.pending.get(destination)

        if existing is not None:
            existing.deadline = min(existing.deadline, deadline)

            self._bounded_set(existing.reasons, reason)

            return

        if len(self.pending) >= MAX_PENDING_DESTINATIONS:
            self.log.warning(
                "Pending unicast RA limit reached; coalescing requests into multicast"
            )

            self._enqueue_locked(MULTICAST_DESTINATION, deadline, "RS overflow")

            return

        self.pending[destination] = PendingTransmission(deadline, {reason})

    def request_ra(
        self,
        reason: str,
        *,
        destination: Destination = (MULTICAST_DESTINATION),
        rs_response: bool = False,
    ) -> None:
        if self.stop_event.is_set() or self.binding_snapshot() is None:
            return

        now = time.monotonic()

        deadline = now

        if rs_response:
            deadline += random.uniform(0.0, MAX_RA_DELAY_TIME)

        with self.condition:
            self._enqueue_locked(destination, deadline, reason)

            self.condition.notify_all()

    def schedule_ula_retry(self, device_mac: str) -> None:
        with self.condition:
            self.pending_ula_retries.pop(device_mac, None)

            self.pending_ula_retries[device_mac] = time.monotonic() + ULA_RETRY_DELAY

            while len(self.pending_ula_retries) > MAX_TRACKED_DEVICES:
                self.pending_ula_retries.popitem(last=False)

            self.condition.notify_all()

    def _process_due_retries_locked(self, now: float) -> None:
        # Every insert uses monotonic() + the same retry delay, so order is by due time.
        while self.pending_ula_retries:
            device_mac, deadline = next(iter(self.pending_ula_retries.items()))
            if deadline > now:
                break
            self.pending_ula_retries.popitem(last=False)
            confirmed_at = self.confirmed_ula_devices.get(device_mac)
            if confirmed_at is not None and now - confirmed_at < ULA_CONFIRMATION_TTL:
                continue
            self.log.info("No ULA DAD seen for %s; scheduling one retry", device_mac)
            self._enqueue_locked(
                MULTICAST_DESTINATION, now, f"ULA retry for {device_mac}"
            )

    def _next_internal_deadline_locked(self) -> float | None:
        deadline = self.next_periodic_deadline if self.periodic_enabled else None
        if self.pending_ula_retries:
            retry = next(iter(self.pending_ula_retries.values()))
            deadline = retry if deadline is None else min(deadline, retry)
        return deadline

    def _legal_deadline(self, destination, pending):
        if destination.multicast and self.last_multicast_sent_timestamp > 0.0:
            return max(
                pending.deadline,
                self.last_multicast_sent_timestamp + MIN_DELAY_BETWEEN_RAS,
            )
        return pending.deadline

    def permit_presence_trigger(self, device_mac: str) -> bool:
        now = time.monotonic()
        with self.condition:
            self._cleanup_device_state_locked(now)
            previous = self.last_presence_by_mac.get(device_mac)
            self._put_bounded(self.last_presence_by_mac, device_mac, now)
            return previous is None or (now - previous >= PRESENCE_COOLDOWN)

    def scheduler_worker(self):
        try:
            self._scheduler_loop()
        finally:
            self._close_sender()

    def _scheduler_loop(self) -> None:
        while not self.stop_event.is_set():
            selected_destination: Destination | None = None

            selected_request: PendingTransmission | None = None

            selected_generation = 0

            with self.condition:
                while not self.stop_event.is_set():
                    now = time.monotonic()

                    self._cleanup_device_state_locked(now)

                    self._process_due_retries_locked(now)

                    if (
                        self.periodic_enabled
                        and self.next_periodic_deadline is not None
                        and now >= self.next_periodic_deadline
                    ):
                        self.next_periodic_deadline = None

                        self._enqueue_locked(
                            MULTICAST_DESTINATION, now, "Periodic advertisement"
                        )

                    binding = self.binding_snapshot()

                    if self._send_socket is not None and (
                        binding is None or binding.generation != self._send_generation
                    ):
                        self._close_sender()

                    if (
                        binding is not None
                        and self.pending
                        and not self.send_in_progress
                    ):
                        (destination, pending) = min(
                            self.pending.items(),
                            key=lambda item: self._legal_deadline(*item),
                        )
                        legal_time = self._legal_deadline(destination, pending)

                        if now >= legal_time:
                            selected_destination = destination

                            selected_request = self.pending.pop(destination)

                            selected_generation = binding.generation

                            self.send_in_progress = True
                            break

                    wake_at = self._next_internal_deadline_locked()

                    if self.pending:
                        legal_wake = min(
                            self._legal_deadline(dst, req)
                            for dst, req in self.pending.items()
                        )

                        if wake_at is None:
                            wake_at = legal_wake
                        else:
                            wake_at = min(wake_at, legal_wake)

                    timeout = None if wake_at is None else max(0.0, wake_at - now)

                    self.condition.wait(timeout=timeout)

            if self.stop_event.is_set():
                break

            if selected_destination is None or selected_request is None:
                continue

            success = self.transmit_ra(
                selected_destination, selected_request.reasons, selected_generation
            )

            with self.condition:
                self.send_in_progress = False

                binding = self.binding_snapshot()

                if (
                    success
                    and binding is not None
                    and binding.generation == selected_generation
                ):
                    sent_at = time.monotonic()

                    if selected_destination.multicast:
                        self.last_multicast_sent_timestamp = sent_at

                    if selected_destination.multicast and self.initial_ra_remaining > 0:
                        self.initial_ra_remaining -= 1

                        if self.initial_ra_remaining > 0:
                            number = INITIAL_RA_COUNT - self.initial_ra_remaining + 1

                            self._enqueue_locked(
                                MULTICAST_DESTINATION,
                                sent_at + INITIAL_RA_INTERVAL,
                                f"Initial RA {number}/{INITIAL_RA_COUNT}",
                            )

                        else:
                            self.periodic_enabled = True

                    if selected_destination.multicast and self.periodic_enabled:
                        self.next_periodic_deadline = sent_at + random.uniform(
                            MIN_PERIODIC_INTERVAL, MAX_PERIODIC_INTERVAL
                        )

                self.condition.notify_all()

    # --------------------------------------------------------
    # RA construction and transmission
    # --------------------------------------------------------

    @staticmethod
    def build_ra_packet(binding: InterfaceBinding, destination: Destination):
        return (
            Ether(src=binding.mac, dst=destination.mac)
            / IPv6(src=binding.link_local, dst=destination.ipv6, hlim=255)
            / ICMPv6ND_RA(routerlifetime=0, chlim=0, M=0, O=0)
            / ICMPv6NDOptSrcLLAddr(lladdr=binding.mac)
            / ICMPv6NDOptPrefixInfo(
                prefix=str(ULA_NET.network_address),
                prefixlen=ULA_NET.prefixlen,
                L=1,
                A=1,
                validlifetime=(PREFIX_VALID_LIFETIME),
                preferredlifetime=(PREFIX_PREFERRED_LIFETIME),
            )
            / ICMPv6NDOptRDNSS(
                dns=[str(LOCAL_DNS_ADDR), str(SECONDARY_DNS_ADDR)],
                lifetime=RDNSS_LIFETIME,
            )
        )

    def _close_sender(self):
        sender, self._send_socket = self._send_socket, None
        self._send_generation = -1
        self._multicast_frame = None
        if sender is not None:
            try:
                sender.close()
            except Exception as exc:
                self.log.warning("Send socket close failed: %s", exc)

    def _frame_for(self, binding, destination):
        if self._send_generation != binding.generation or self._multicast_frame is None:
            self._close_sender()
            self._multicast_frame = bytes(
                self.build_ra_packet(binding, MULTICAST_DESTINATION)
            )
            self._send_generation = binding.generation
        if destination.multicast:
            return self._multicast_frame
        # Only Ethernet destination, IPv6 destination and checksum differ.
        frame = bytearray(self._multicast_frame)
        frame[0:6] = bytes.fromhex(destination.mac.replace(":", ""))
        frame[38:54] = ipaddress.IPv6Address(destination.ipv6).packed
        frame[56:58] = b"\0\0"
        pseudo = bytes(frame[22:54]) + struct.pack("!I3xB", len(frame) - 54, 58)
        struct.pack_into("!H", frame, 56, checksum(pseudo + bytes(frame[54:])))
        return bytes(frame)

    def transmit_ra(
        self, destination: Destination, reasons: set[str], generation: int
    ) -> bool:
        reason_text = " + ".join(sorted(reasons)) or "Scheduled"
        for attempt in range(1, MAX_SEND_ATTEMPTS + 1):
            if self.stop_event.is_set():
                return False
            binding = self.binding_snapshot()
            if binding is None or binding.generation != generation:
                return False
            try:
                frame = self._frame_for(binding, destination)
                if self._send_socket is None:
                    # Resolve by GUID rather than a potentially reused interface index.
                    self._send_socket = conf.L2socket(
                        iface=binding.iface,
                        promisc=False,
                        filter="ip6 and ip6[40] = 255",
                    )
                self.log.info(
                    "Sending %s RA to IPv6=%s MAC=%s (%s), attempt %d/%d",
                    "multicast" if destination.multicast else "unicast",
                    destination.ipv6,
                    destination.mac,
                    reason_text,
                    attempt,
                    MAX_SEND_ATTEMPTS,
                )
                result = self._send_socket.send(frame)
                # libpcap returns zero on success; native sockets may return byte count.
                if result is not None and result < 0:
                    raise OSError("Npcap packet injection failed")
                return True
            except Exception as exc:
                self._close_sender()
                self.log.error(
                    "RA send failed, attempt %d/%d: %s", attempt, MAX_SEND_ATTEMPTS, exc
                )
                if attempt < MAX_SEND_ATTEMPTS and self.stop_event.wait(
                    SEND_FAILURE_RETRY_DELAY
                ):
                    return False
        self.invalidate_binding(generation, "repeated packet transmission failure")
        return False

    # --------------------------------------------------------
    # Packet validation and handling
    # --------------------------------------------------------

    @staticmethod
    def solicited_node_multicast(
        target: ipaddress.IPv6Address,
    ) -> ipaddress.IPv6Address:
        prefix = int(ipaddress.IPv6Address("ff02::1:ff00:0"))

        return ipaddress.IPv6Address(prefix | (int(target) & 0xFFFFFF))

    @staticmethod
    def valid_nd_packet(
        packet,
        *,
        verify_checksum: bool = True,
    ) -> bool:
        ipv6 = packet.getlayer(IPv6)
        if ipv6 is None:
            return False
        data = ipv6.original or bytes(ipv6)
        if len(data) < 40 or data[0] >> 4 != 6:
            return False
        end = 40 + int.from_bytes(data[4:6], "big")
        if end > len(data) or end == 40:
            return False
        nh, offset = data[6], 40
        while nh != 58:
            if nh == 44:  # RFC 6980, including atomic fragments
                return False
            if nh not in (0, 43, 60, 51) or offset + 2 > end:
                return False
            size = (
                (data[offset + 1] + 2) * 4 if nh == 51 else (data[offset + 1] + 1) * 8
            )
            if offset + size > end:
                return False
            nh, offset = data[offset], offset + size
        if offset + 4 > end:
            return False
        kind = data[offset]
        minimum = ND_MIN_LENGTH.get(kind)
        if minimum is None or end - offset < minimum or data[offset + 1] != 0:
            return False
        payload = data[offset:end]
        if offset == 40:
            pseudo = data[8:40] + struct.pack("!I3xB", len(payload), 58)
            if verify_checksum and checksum(pseudo + payload):
                return False
        else:
            nd_type = ND_TYPES[kind]
            layer = packet.getlayer(nd_type)
            if layer is None:
                return False
            
            if verify_checksum and in6_chksum(58, layer, payload):
                return False
        option = offset + minimum
        while option < end:
            if option + 2 > end:
                return False
            size = data[option + 1] * 8
            if size == 0 or option + size > end:
                return False
            option += size
        return True

    def packet_handler(self, packet, capture_generation: int) -> None:
        binding = self.binding_snapshot()
        if binding is None or binding.generation != capture_generation:
            return
    
        # 1. הגנה מפני קריסה: וידוא קיום שכבת Ethernet
        if not packet.haslayer(Ether):
            return
    
        # 2. זיהוי נוכחות IPv4 של לקוח קצה בלבד (ללא מענה לראוטר)
        dhcp_client = (
            packet.haslayer(BOOTP)
            and int(packet[BOOTP].op) == 1
            and normalize_mac(packet[Ether].dst) == "ff:ff:ff:ff:ff:ff"
        )
        arp = packet.getlayer(ARP)
        arp_client = (
            arp is not None
            and normalize_mac(packet[Ether].dst)
            == "ff:ff:ff:ff:ff:ff"
            and int(arp.op) == 1
            and (
                str(arp.psrc) == "0.0.0.0"
                or str(arp.psrc) == str(arp.pdst)
            )
        )
    
        if dhcp_client or arp_client:
            src_mac = normalize_mac(packet[Ether].src)
            if is_unicast_mac(src_mac) and src_mac != binding.mac:
                if self.permit_presence_trigger(src_mac):
                    self.log.info("Client presence detected via IPv4 Broadcast for %s; scheduling RA", src_mac)
                    self.request_ra(f"Presence trigger for {src_mac}")
    
        if not packet.haslayer(IPv6):
            return

        if not self.valid_nd_packet(packet):
            checksum_only_failure = (
                ND_CHECKSUM_DIAGNOSTICS
                and any(
                    packet.haslayer(nd_type)
                    for nd_type in ND_TYPES.values()
                )
                and self.valid_nd_packet(
                    packet,
                    verify_checksum=False,
                )
            )
        
            if checksum_only_failure:
                now = time.monotonic()
        
                if (
                    now - self.last_checksum_diagnostic
                    >= ND_DIAGNOSTIC_LOG_INTERVAL
                ):
                    self.last_checksum_diagnostic = now
        
                    self.log.warning(
                        "ND packet rejected only because of checksum: "
                        "MAC=%s IPv6=%s -> %s",
                        packet[Ether].src,
                        packet[IPv6].src,
                        packet[IPv6].dst,
                    )
        
            return

        ipv6 = packet[IPv6]

        # כל חבילת NDP תקינה חייבת להגיע
        # עם IPv6 Hop Limit של 255.
        if ipv6.hlim != 255:
            return

        src_mac = normalize_mac(packet[Ether].src)

        if not is_unicast_mac(src_mac) or src_mac == binding.mac:
            return

        try:
            src_ip = ipaddress.IPv6Address(ipv6.src)

            dst_ip = ipaddress.IPv6Address(ipv6.dst)

        except ValueError:
            return

        # ====================================================
        # Router Advertisement מנתב קיים
        # ====================================================

        if packet.haslayer(ICMPv6ND_RA):
            ra = packet[ICMPv6ND_RA]

            if ra.code != 0 or not src_ip.is_link_local:
                return

            if ra.routerlifetime > 0:
                source_key = f"{src_mac}/{src_ip}"

                if self.permit_primary_ra_followup(source_key):
                    self.log.info(
                        "Primary router RA detected from %s (%s)", src_ip, src_mac
                    )

                    self.request_ra("Follow-up to primary router RA")

            return

        # ====================================================
        # Router Solicitation
        # ====================================================

        if packet.haslayer(ICMPv6ND_RS):
            rs = packet[ICMPv6ND_RS]

            if rs.code != 0 or not (src_ip.is_link_local or src_ip.is_unspecified):
                return

            # RS עם מקור :: אינו רשאי לכלול
            # Source Link-Layer Address Option.
            if src_ip.is_unspecified and packet.haslayer(ICMPv6NDOptSrcLLAddr):
                return

            if not self.permit_rs(src_mac):
                return

            if src_ip.is_link_local:
                destination = Destination(
                    ipv6=str(src_ip), mac=src_mac, multicast=False
                )

                response_type = "unicast"

            else:
                destination = MULTICAST_DESTINATION

                response_type = "multicast"

            self.log.info(
                "RS received from IPv6=%s MAC=%s; scheduling %s reply",
                src_ip,
                src_mac,
                response_type,
            )

            self.request_ra(
                f"RS from {src_mac}", destination=destination, rs_response=True
            )

            return

        # ====================================================
        # DAD Neighbor Solicitation
        # ====================================================

        if not packet.haslayer(ICMPv6ND_NS) or not src_ip.is_unspecified:
            return

        ns = packet[ICMPv6ND_NS]

        if ns.code != 0 or packet.haslayer(ICMPv6NDOptSrcLLAddr):
            return

        try:
            target = ipaddress.IPv6Address(ns.tgt)
        except ValueError:
            return

        if target.is_unspecified or target.is_multicast:
            return

        expected_destination = self.solicited_node_multicast(target)

        if dst_ip != expected_destination:
            return

        # ====================================================
        # Link-Local DAD
        # ====================================================

        if target.is_link_local:
            self.reset_device_state(src_mac)

            self.log.info(
                "Link-Local DAD detected for %s (%s); device state reset",
                src_mac,
                target,
            )

            return

        # ====================================================
        # ULA-DAD
        # ====================================================

        if target in ULA_NET:
            self.confirm_ula_device(src_mac)

            self.log.info("Device %s applied ULA (%s)", src_mac, target)

            return

        # ====================================================
        # GUA-DAD
        # ====================================================

        if target in GUA_NET:
            if self.was_ula_recently_confirmed(src_mac):
                self.log.info(
                    "Additional GUA DAD ignored for confirmed device %s (%s)",
                    src_mac,
                    target,
                )

                return

            self.log.info(
                "Device %s configured GUA (%s); scheduling multicast RA",
                src_mac,
                target,
            )

            # DAD מגיע עם מקור :: ואינו RS.
            # לכן התגובה נשארת Multicast.
            self.request_ra(f"Post-GUA for {src_mac}")

            self.schedule_ula_retry(src_mac)

    def safe_packet_handler(self, packet, capture_generation: int) -> None:
        try:
            with self.condition:
                self.packet_handler(packet, capture_generation)
        except Exception:
            self.log.exception("Packet callback failed")

    # --------------------------------------------------------
    # Persistent Sniffer
    # --------------------------------------------------------

    def sniffer_worker(self) -> None:
        retry_delay = 1.0

        while not self.stop_event.is_set():
            binding = self.binding_snapshot()

            if binding is None:
                self.stop_event.wait(0.5)
                continue

            sniffer: AsyncSniffer | None = None
            mcast_sock: socket.socket | None = None

            try:
                generation = binding.generation

                try:
                    mcast_sock = self._join_all_routers_group(binding.ipv6_index)
                except OSError as exc:
                    self.log.warning(
                        "Could not join ff02::2 on IPv6 index %d: %s",
                        binding.ipv6_index,
                        exc,
                    )
    
                bpf_filter = (
                    "(ip6 and ("
                    "ip6[6] = 58 or ip6[6] = 0 or ip6[6] = 43 or "
                    "ip6[6] = 44 or ip6[6] = 51 or ip6[6] = 60"
                    ")) or arp or (ip and udp and (port 67 or port 68))"
                )
                
                sniffer = AsyncSniffer(
                    iface=binding.iface,
                    filter=bpf_filter,
                    promisc=True,
                    prn=lambda packet, gen=generation: self.safe_packet_handler(packet, gen),
                    store=False,
                )
        
                sniffer.start()
        
                self.log.info(
                    "ICMPv6 sniffer started on interface index %d", binding.index
                )

                retry_delay = 1.0

                while not self.stop_event.wait(0.5):
                    current = self.binding_snapshot()

                    if current is None or current.generation != generation:
                        break

                    if sniffer.thread is not None and not sniffer.thread.is_alive():
                        # join מעלה מחדש את שגיאת
                        # Scapy/Npcap המקורית.
                        sniffer.join()

                        raise RuntimeError("Npcap sniffer stopped unexpectedly")

            except Exception as exc:
                self.log.error("Sniffer failure: %s", exc)

                self.invalidate_binding(binding.generation, f"sniffer failure: {exc}")

                if self.stop_event.wait(retry_delay):
                    break

                retry_delay = min(retry_delay * 2.0, 30.0)

            finally:
                self._stop_sniffer(sniffer)
                if mcast_sock is not None:
                    try:
                        mcast_sock.close()
                    except OSError as exc:
                        self.log.warning("Multicast socket close failed: %s", exc)

    def _stop_sniffer(self, sniffer):
        if sniffer is None or sniffer.thread is None or not sniffer.thread.is_alive():
            return
        try:
            if sniffer.running:
                sniffer.stop(join=False)
        except Exception as exc:
            self.log.warning("Sniffer stop request failed: %s", exc)
        try:
            sniffer.join(timeout=SNIFFER_STOP_TIMEOUT)
        except Exception as exc:
            self.log.warning("Sniffer shutdown reported: %s", exc)
        if sniffer.thread.is_alive():
            # Never start more capture threads while an old one is stuck.
            self.log.error("Npcap capture did not stop; stopping engine")
            self.failure_event.set()
            self.stop_event.set()
            self.monitor_wakeup.set()
            with self.condition:
                self.condition.notify_all()

    # --------------------------------------------------------
    # Startup and Shutdown
    # --------------------------------------------------------

    def start(self) -> None:
        self.threads = [
            threading.Thread(
                target=(self.interface_monitor_worker),
                name="Interface-Monitor",
                daemon=False,
            ),
            threading.Thread(
                target=(self.scheduler_worker), name="RA-Scheduler", daemon=False
            ),
            threading.Thread(
                target=(self.sniffer_worker), name="ICMPv6-Sniffer", daemon=False
            ),
        ]

        for thread in self.threads:
            thread.start()

        self.log.info("Smart Router Engine started; press Ctrl+C to stop")

    def stop(self) -> None:
        with self.stop_lock:
            if self.stopped:
                return

            self.stopped = True

            self.log.info("Stopping Smart Router Engine")

            self.stop_event.set()
            self.monitor_wakeup.set()

            with self.condition:
                self.condition.notify_all()

            for thread in self.threads:
                thread.join(timeout=10.0)

                if thread.is_alive():
                    self.log.error(
                        "Worker did not stop within timeout: %s", thread.name
                    )

            self.log.info("Smart Router Engine stopped")


# ============================================================
# 6. Process Entry Point
# ============================================================


class SingleInstance:
    """A Windows named mutex is released by the OS even after process failure."""

    def __init__(self):
        from ctypes import wintypes

        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateMutexW.argtypes = [
            ctypes.c_void_p,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        ]
        self.api.CreateMutexW.restype = wintypes.HANDLE
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.api.CloseHandle.restype = wintypes.BOOL
        self.handle = self.api.CreateMutexW(None, False, r"Global\RaEngine.Broadcast")
        error = ctypes.get_last_error()
        if not self.handle:
            raise ctypes.WinError(error)
        if error == 183:  # ERROR_ALREADY_EXISTS
            self.close()
            raise RuntimeError("Another RA engine process is already running")

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


def main() -> int:
    if sys.platform != "win32":
        print("This program requires Windows and Npcap.", file=sys.stderr)

        return 2

    instance = None
    try:
        validate_configuration()
        instance = SingleInstance()
        logger, listener = configure_logging()

    except Exception as exc:
        if instance is not None:
            instance.close()
        print(f"Startup configuration failed: {exc}", file=sys.stderr)

        return 2

    engine = RouterAdvertisementEngine(logger)

    def request_shutdown(_signum=None, _frame=None) -> None:
        engine.stop_event.set()
        engine.monitor_wakeup.set()

        with engine.condition:
            engine.condition.notify_all()

    for signal_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        process_signal = getattr(signal, signal_name, None)

        if process_signal is not None:
            signal.signal(process_signal, request_shutdown)

    try:
        if not is_elevated_windows_process():
            logger.error(
                "Administrator privileges are required for raw Layer-2 capture/send"
            )

            return 2

        engine.start()

        while not engine.stop_event.wait(1.0):
            dead_workers = [
                thread.name for thread in engine.threads if not thread.is_alive()
            ]

            if dead_workers:
                logger.critical("Worker failure detected: %s", ", ".join(dead_workers))

                return 1

        return 1 if engine.failure_event.is_set() else 0

    except KeyboardInterrupt:
        return 0

    except Exception:
        logger.exception("Fatal process failure")

        return 1

    finally:
        engine.stop()
        for handler in logger.handlers:
            if isinstance(handler, BoundedQueueHandler):
                handler.stop_accepting()
                if handler.dropped:
                    print(
                        f"Log queue overload: {handler.dropped} records dropped",
                        file=sys.stderr,
                    )
        try:
            listener.stop()
        finally:
            instance.close()


if __name__ == "__main__":
    raise SystemExit(main())
