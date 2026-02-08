"""Tests for the fpcap Python bindings."""

import os
import pytest
import fpcap

TRACEFILE_DIR = os.path.join(os.path.dirname(__file__), "tracefiles")


def tracefile(name):
    return os.path.join(TRACEFILE_DIR, name)


# ---------------------------------------------------------------------------
# Basic API tests
# ---------------------------------------------------------------------------

class TestImport:
    def test_public_symbols(self):
        assert hasattr(fpcap, "PacketReader")
        assert hasattr(fpcap, "Packet")
        assert hasattr(fpcap, "TraceInterface")
        assert hasattr(fpcap, "MagicNumber")
        assert hasattr(fpcap, "DataLinkType")
        assert hasattr(fpcap, "Writer")
        assert hasattr(fpcap, "__version__")


class TestEnums:
    def test_data_link_type_values(self):
        assert fpcap.DataLinkType.DLT_NULL == 0
        assert fpcap.DataLinkType.DLT_EN10MB == 1
        assert fpcap.DataLinkType.DLT_IEEE802_5 == 6
        assert fpcap.DataLinkType.DLT_PPP == 9
        assert fpcap.DataLinkType.DLT_FDDI == 10
        assert fpcap.DataLinkType.DLT_RAW == 101
        assert fpcap.DataLinkType.DLT_IEEE802_11 == 105
        assert fpcap.DataLinkType.DLT_LINUX_SLL == 113
        assert fpcap.DataLinkType.DLT_LINUX_SLL2 == 276

    def test_magic_number_values(self):
        assert fpcap.MagicNumber.PCAP_MICROSECONDS == 0xA1B2C3D4
        assert fpcap.MagicNumber.PCAP_NANOSECONDS == 0xA1B23C4D
        assert fpcap.MagicNumber.PCAPNG == 0x0A0D0D0A
        assert fpcap.MagicNumber.ZSTD == 0xFD2FB528
        assert fpcap.MagicNumber.MODIFIED_PCAP == 0xA1B2CD34

    def test_writer_format_values(self):
        assert fpcap.WriterFormat.AUTO is not None
        assert fpcap.WriterFormat.PCAP is not None
        assert fpcap.WriterFormat.PCAPNG is not None


class TestPacketDefault:
    def test_default_values(self):
        p = fpcap.Packet()
        assert p.timestamp_seconds == 0
        assert p.timestamp_microseconds == 0
        assert p.capture_length == 0
        assert p.length == 0
        assert p.data_link_type == 0
        assert p.interface_index == -1
        assert p.data == b""

    def test_repr(self):
        p = fpcap.Packet()
        assert "Packet" in repr(p)


# ---------------------------------------------------------------------------
# PCAP format tests
# ---------------------------------------------------------------------------

class TestExamplePcap:
    """Tests for example.pcap — standard PCAP, Ethernet, 4631 packets."""

    def test_packet_count(self):
        reader = fpcap.PacketReader(tracefile("example.pcap"))
        packets = list(reader)
        assert len(packets) == 4631

    def test_data_link_type(self):
        reader = fpcap.PacketReader(tracefile("example.pcap"))
        packet = reader.next_packet()
        assert packet.data_link_type == 1  # DLT_EN10MB

    def test_packet_properties(self):
        reader = fpcap.PacketReader(tracefile("example.pcap"))
        packet = reader.next_packet()
        assert packet.capture_length > 0
        assert packet.length > 0
        assert isinstance(packet.data, bytes)
        assert len(packet.data) == packet.capture_length

    def test_filepath(self):
        path = tracefile("example.pcap")
        reader = fpcap.PacketReader(path)
        assert reader.filepath == path


class TestLinuxCookedPcap:
    """Tests for linux-cooked-unsw-nb15.pcap — Linux SLL, 1000 packets."""

    def test_packet_count(self):
        reader = fpcap.PacketReader(tracefile("linux-cooked-unsw-nb15.pcap"))
        packets = list(reader)
        assert len(packets) == 1000

    def test_data_link_type(self):
        reader = fpcap.PacketReader(tracefile("linux-cooked-unsw-nb15.pcap"))
        packet = reader.next_packet()
        assert packet.data_link_type == 113  # DLT_LINUX_SLL


class TestFritzboxModifiedPcap:
    """Tests for fritzbox-ip.pcap — Modified PCAP, Raw IP, 5 packets."""

    def test_packet_count(self):
        reader = fpcap.PacketReader(tracefile("fritzbox-ip.pcap"))
        packets = list(reader)
        assert len(packets) == 5

    def test_data_link_type(self):
        reader = fpcap.PacketReader(tracefile("fritzbox-ip.pcap"))
        packet = reader.next_packet()
        assert packet.data_link_type == 101  # DLT_RAW

    def test_next_packet_returns_none_when_exhausted(self):
        reader = fpcap.PacketReader(tracefile("fritzbox-ip.pcap"))
        while reader.next_packet() is not None:
            pass
        assert reader.is_exhausted()
        assert reader.next_packet() is None


class TestRicsPcap:
    """Tests for RICS2021 PCAP — standard PCAP, 6718 packets."""

    def test_packet_count(self):
        reader = fpcap.PacketReader(tracefile("RICS2021_787__fwscada_20200625_160926.pcap"))
        packets = list(reader)
        assert len(packets) == 6718


# ---------------------------------------------------------------------------
# PcapNG format tests
# ---------------------------------------------------------------------------

class TestPcapngExample:
    """Tests for pcapng-example.pcapng — PcapNG, mixed DLTs, 159 packets."""

    def test_packet_count(self):
        reader = fpcap.PacketReader(tracefile("pcapng-example.pcapng"))
        packets = list(reader)
        assert len(packets) == 159

    def test_iteration(self):
        reader = fpcap.PacketReader(tracefile("pcapng-example.pcapng"))
        count = 0
        for packet in reader:
            count += 1
            assert packet.capture_length > 0
        assert count == 159

    def test_packet_data(self):
        reader = fpcap.PacketReader(tracefile("pcapng-example.pcapng"))
        for packet in reader:
            assert isinstance(packet.data, bytes)
            assert len(packet.data) == packet.capture_length


class TestManyInterfacesPcapng:
    """Tests for many_interfaces-1.pcapng — PcapNG with 11 interfaces."""

    def test_trace_interfaces_count(self):
        reader = fpcap.PacketReader(tracefile("many_interfaces-1.pcapng"))
        interfaces = reader.get_trace_interfaces()
        assert len(interfaces) == 11

    def test_interface_names(self):
        reader = fpcap.PacketReader(tracefile("many_interfaces-1.pcapng"))
        interfaces = reader.get_trace_interfaces()
        expected_names = [
            "en0", "awdl0", "bridge0", "vboxnet0", "utun0",
            "en1", "vboxnet1", "en2", "p2p0",
        ]
        for i, name in enumerate(expected_names):
            assert interfaces[i].name == name

    def test_interface_filter(self):
        reader = fpcap.PacketReader(tracefile("many_interfaces-1.pcapng"))
        interfaces = reader.get_trace_interfaces()
        for iface in interfaces:
            assert iface.filter == "host 192.168.1.139"

    def test_interface_os(self):
        reader = fpcap.PacketReader(tracefile("many_interfaces-1.pcapng"))
        interfaces = reader.get_trace_interfaces()
        for iface in interfaces:
            assert iface.os == "Mac OS X 10.10.4, build 14E46 (Darwin 14.4.0)"

    def test_interface_timestamp_resolution(self):
        reader = fpcap.PacketReader(tracefile("many_interfaces-1.pcapng"))
        interfaces = reader.get_trace_interfaces()
        for iface in interfaces:
            assert iface.timestamp_resolution == 1000000

    def test_get_single_interface(self):
        reader = fpcap.PacketReader(tracefile("many_interfaces-1.pcapng"))
        iface = reader.get_trace_interface(0)
        assert iface.name == "en0"

    def test_interface_repr(self):
        reader = fpcap.PacketReader(tracefile("many_interfaces-1.pcapng"))
        iface = reader.get_trace_interface(0)
        assert "TraceInterface" in repr(iface)
        assert "en0" in repr(iface)


# ---------------------------------------------------------------------------
# Zstd compressed format tests
# ---------------------------------------------------------------------------

class TestExamplePcapZst:
    """Tests for example.pcap.zst — Zstd-compressed PCAP."""

    def test_packet_count(self):
        reader = fpcap.PacketReader(tracefile("example.pcap.zst"))
        packets = list(reader)
        assert len(packets) == 4631

    def test_data_link_type(self):
        reader = fpcap.PacketReader(tracefile("example.pcap.zst"))
        packet = reader.next_packet()
        assert packet.data_link_type == 1


class TestLinuxCookedPcapZst:
    """Tests for linux-cooked-unsw-nb15.pcap.zst — Zstd-compressed PCAP."""

    def test_packet_count(self):
        reader = fpcap.PacketReader(tracefile("linux-cooked-unsw-nb15.pcap.zst"))
        packets = list(reader)
        assert len(packets) == 1000

    def test_data_link_type(self):
        reader = fpcap.PacketReader(tracefile("linux-cooked-unsw-nb15.pcap.zst"))
        packet = reader.next_packet()
        assert packet.data_link_type == 113


class TestFritzboxPcapZst:
    """Tests for fritzbox-ip.pcap.zst — Zstd-compressed Modified PCAP."""

    def test_packet_count(self):
        reader = fpcap.PacketReader(tracefile("fritzbox-ip.pcap.zst"))
        packets = list(reader)
        assert len(packets) == 5

    def test_data_link_type(self):
        reader = fpcap.PacketReader(tracefile("fritzbox-ip.pcap.zst"))
        packet = reader.next_packet()
        assert packet.data_link_type == 101


class TestPcapngExampleZst:
    """Tests for pcapng-example.pcapng.zst — Zstd-compressed PcapNG."""

    def test_packet_count(self):
        reader = fpcap.PacketReader(tracefile("pcapng-example.pcapng.zst"))
        packets = list(reader)
        assert len(packets) == 159


class TestPcapngExampleZstd:
    """Tests for pcapng-example.pcapng.zstd — Zstd-compressed PcapNG (.zstd extension)."""

    def test_packet_count(self):
        reader = fpcap.PacketReader(tracefile("pcapng-example.pcapng.zstd"))
        packets = list(reader)
        assert len(packets) == 159


# ---------------------------------------------------------------------------
# Error handling tests
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_invalid_file_path(self):
        with pytest.raises(RuntimeError):
            fpcap.PacketReader("/nonexistent/file.pcap")

    def test_reader_is_exhausted_after_iteration(self):
        reader = fpcap.PacketReader(tracefile("fritzbox-ip.pcap"))
        list(reader)
        assert reader.is_exhausted()

    def test_second_iteration_yields_nothing(self):
        reader = fpcap.PacketReader(tracefile("fritzbox-ip.pcap"))
        first = list(reader)
        second = list(reader)
        assert len(first) == 5
        assert len(second) == 0
