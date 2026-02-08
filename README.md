![](https://fpcap.net/images/fpcap_logo.svg)

# FPCAP Python - Python bindings for the fpcap packet capture library

[![build](https://github.com/fpcap/fpcap-python/actions/workflows/build.yml/badge.svg)](https://github.com/fpcap/fpcap-python/actions/workflows/build.yml)
[![GitHub release](https://img.shields.io/github/v/release/fpcap/fpcap-python)](https://github.com/fpcap/fpcap-python/releases)
[![license](https://img.shields.io/github/license/fpcap/fpcap-python)](https://github.com/fpcap/fpcap-python/blob/main/LICENSE)
[![Python 3.9](https://img.shields.io/badge/python-3.9-blue)](https://www.python.org/)
[![Python 3.10](https://img.shields.io/badge/python-3.10-blue)](https://www.python.org/)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue)](https://www.python.org/)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue)](https://www.python.org/)
[![Python 3.13](https://img.shields.io/badge/python-3.13-blue)](https://www.python.org/)
[![Python 3.14](https://img.shields.io/badge/python-3.14-blue)](https://www.python.org/)

Python bindings for the [fpcap](https://github.com/fpcap/fpcap) C++ library, a modern, simple and lightweight
alternative to libpcap for reading packet capture files. Built with [pybind11](https://github.com/pybind/pybind11).

## Features

- Read packets from Pcap, PcapNG, and Modified Pcap files
- Write packets to Pcap and PcapNG files
- Memory-mapped I/O for efficient processing of large files
- Zstd decompression support (.zst / .zstd files)
- Pythonic iteration over packets
- Access to PcapNG metadata (comments, OS, hardware, interfaces)
- Cross-platform: Linux, macOS, Windows

## Installation

```shell
pip install fpcap
```

### From source

```shell
git clone https://github.com/fpcap/fpcap-python.git
cd fpcap-python
pip install .
```

## Usage

### Reading packets

Iterate over packets from a Pcap or PcapNG file:

```python
import fpcap

reader = fpcap.PacketReader("capture.pcap")
for packet in reader:
    print(f"ts={packet.timestamp_seconds}.{packet.timestamp_microseconds} "
          f"len={packet.length} caplen={packet.capture_length}")
    raw_bytes = packet.data  # bytes object
```

Or using the explicit reading API:

```python
import fpcap

reader = fpcap.PacketReader("capture.pcap")
while not reader.is_exhausted():
    packet = reader.next_packet()
    if packet is not None:
        # process packet
        pass
```

### Writing packets

Copy packets from one file to another:

```python
import fpcap

reader = fpcap.PacketReader("input.pcap")
writer = fpcap.Writer.get_writer("output.pcap")

for packet in reader:
    writer.write(packet)
```

### PcapNG metadata

Access file-level metadata from PcapNG files:

```python
import fpcap

reader = fpcap.PacketReader("capture.pcapng")
print(reader.get_comment())
print(reader.get_os())
print(reader.get_hardware())
print(reader.get_user_application())

for iface in reader.get_trace_interfaces():
    print(f"{iface.name} (DLT={iface.data_link_type})")
```

## API Reference

### `PacketReader`

| Method / Property                   | Description                                       |
|-------------------------------------|---------------------------------------------------|
| `PacketReader(filepath, mmap=True)` | Open a capture file for reading                   |
| `next_packet()`                     | Read the next packet, returns `None` if exhausted |
| `is_exhausted()`                    | Check if all packets have been read               |
| `filepath`                          | Path of the opened file                           |
| `get_comment()`                     | PcapNG section comment                            |
| `get_os()`                          | PcapNG OS string                                  |
| `get_hardware()`                    | PcapNG hardware string                            |
| `get_user_application()`            | PcapNG user application string                    |
| `get_trace_interfaces()`            | List of `TraceInterface` objects                  |

### `Packet`

| Property                 | Type    | Description                        |
|--------------------------|---------|------------------------------------|
| `timestamp_seconds`      | `int`   | Capture timestamp (seconds)        |
| `timestamp_microseconds` | `int`   | Capture timestamp (microseconds)   |
| `capture_length`         | `int`   | Number of captured bytes           |
| `length`                 | `int`   | Original packet length on the wire |
| `data_link_type`         | `int`   | Link-layer header type             |
| `interface_index`        | `int`   | PcapNG interface index (-1 if N/A) |
| `data`                   | `bytes` | Raw packet bytes                   |

### `Writer`

| Method                                                                | Description                       |
|-----------------------------------------------------------------------|-----------------------------------|
| `Writer.get_writer(filepath, append=False, format=WriterFormat.AUTO)` | Create a writer                   |
| `write(packet)`                                                       | Write a packet to the output file |

## Build Requirements

- Python 3.9 - 3.14
- C++20 compatible compiler (GCC, Clang, MSVC)
- CMake >= 3.16

The C++ dependencies (fpcap, pybind11, zstd) are fetched automatically during the build via CMake FetchContent.

## Contributing

Contributions and feedback are welcome! Feel free to open an issue or a pull request.

## License

This project is released into the public domain under the [Unlicense](LICENSE).
