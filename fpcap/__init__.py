"""fpcap - Python bindings for the fpcap C++ packet capture library."""

from fpcap._fpcap import (
    MagicNumber,
    DataLinkType,
    WriterFormat,
    Packet,
    TraceInterface,
    PacketReader,
    Writer,
)

__version__ = "0.2.0"

__all__ = [
    "MagicNumber",
    "DataLinkType",
    "WriterFormat",
    "Packet",
    "TraceInterface",
    "PacketReader",
    "Writer",
    "__version__",
]
