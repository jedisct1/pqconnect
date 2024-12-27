from os import environ
from os.path import join
from struct import pack

SUPPORTED_MAJOR_VERSIONS = ("1",)
DEFAULT_KEYPATH = "/etc/pqconnect/keys"
CONFIG_PATH = "/etc/pqconnect/config"

# Check if user passed another keypath in as environment variable
try:
    DEFAULT_KEYPATH = environ["KEYPATH"]

except KeyError:
    pass

PRIVSEP_USER = "pqconnect"

# ===netfilterqueue===
# Number of different queue values to try when adding a netfilter queue rule
NUM_QUEUE_ATTEMPTS = 10

# ===DNS===
A_RECORD = 1
DNS_ENCODED_HASH_LEN = 52
DNS_ENCODED_PORT_LEN = 4

# ===Port settings===
PQCPORT_CLIENT = 42423
PQCPORT = 42424
KEYPORT = 42425

# ===Default private IP addresses===
IP_SERVER = "10.42.0.1"
IP_CLIENT = "10.43.0.1"

# ===Key Settings===
MCELIECE_SK_PATH = join(DEFAULT_KEYPATH, "mceliece_sk")
MCELIECE_PK_PATH = join(DEFAULT_KEYPATH, "mceliece_pk")
X25519_SK_PATH = join(DEFAULT_KEYPATH, "x25519_sk")
X25519_PK_PATH = join(DEFAULT_KEYPATH, "x25519_pk")
SESSION_KEY_PATH = join(DEFAULT_KEYPATH, "session_key")
SEG_LEN = 1152

# ===Misc constants===
MAGIC_NUMBER = b"pq1"  # Precedes a pk hash
EPOCH_DURATION_SECONDS = 30
EPOCH_TIMEOUT_SECONDS = 120
MAX_CONNS = 1 << 16
TIDLEN = 32
DAY_SECONDS = 60 * 60 * 24

# https://bench.cr.yp.to/results-stream.html#amd64-samba
CHAIN_KEY_NUM_PACKETS = 18

MAX_CHAIN_LEN = 5 * CHAIN_KEY_NUM_PACKETS
MAX_EPOCHS = 5

# The client will need to download the server's long-term keys at *most* twice
# per day
NUM_PREKEYS = 60 * 60 * 12 // EPOCH_TIMEOUT_SECONDS

# ===msg types===
STATIC_KEY_REQUEST = b"\xf0\x00"
STATIC_KEY_RESPONSE = b"\xf1\x00"
EPHEMERAL_KEY_REQUEST = b"\xf2\x00"
EPHEMERAL_KEY_RESPONSE = b"\xf3\x00"
HANDSHAKE_FAIL = b"\x03\x00"
INITIATION_MSG = b"\x01\x00"
TUNNEL_MSG = b"\x02\x00"
COOKIE_PREFIX = b"pqccookE"
COOKIE_PREFIX_LEN = len(COOKIE_PREFIX)
TIMESTAMP_LEN = 8

HDRLEN = len(TUNNEL_MSG) + TIDLEN + len(pack("!HI", 0, 0))

# DNS resolver utility
DNS_EXAMPLE_HOST: str = "www.pqconnect.net"

# Daemon-related
PIDPATH: str = "/run/pqconnect.pid"
PIDCLIENTPATH: str = "/run/pqconnect-cli.pid"
PIDSERVERPATH: str = "/run/pqconnect-serv.pid"
