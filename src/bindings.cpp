#include <pybind11/pybind11.h>
#include <pybind11/native_enum.h>
#include <pybind11/stl.h>

#include <fpcap/fpcap.hpp>
#include <fpcap/filesystem/Writer.hpp>

namespace py = pybind11;

PYBIND11_MODULE(_fpcap, m) {
    m.doc() = "Python bindings for the fpcap C++ packet capture library";

    // --- MagicNumber enum ---
    py::native_enum<fpcap::MagicNumber>(m, "MagicNumber", "enum.IntEnum")
        .value("PCAP_MICROSECONDS", fpcap::MagicNumber::PCAP_MICROSECONDS)
        .value("PCAP_NANOSECONDS", fpcap::MagicNumber::PCAP_NANOSECONDS)
        .value("PCAPNG", fpcap::MagicNumber::PCAPNG)
        .value("ZSTD", fpcap::MagicNumber::ZSTD)
        .value("MODIFIED_PCAP", fpcap::MagicNumber::MODIFIED_PCAP)
        .value("MODIFIED_PCAP_BE", fpcap::MagicNumber::MODIFIED_PCAP_BE)
        .finalize();

    // --- DataLinkType enum ---
    py::native_enum<fpcap::DataLinkType>(m, "DataLinkType", "enum.IntEnum")
        .value("DLT_NULL", fpcap::DataLinkType::DLT_NULL)
        .value("DLT_EN10MB", fpcap::DataLinkType::DLT_EN10MB)
        .value("DLT_IEEE802_5", fpcap::DataLinkType::DLT_IEEE802_5)
        .value("DLT_PPP", fpcap::DataLinkType::DLT_PPP)
        .value("DLT_FDDI", fpcap::DataLinkType::DLT_FDDI)
        .value("DLT_RAW", fpcap::DataLinkType::DLT_RAW)
        .value("DLT_IEEE802_11", fpcap::DataLinkType::DLT_IEEE802_11)
        .value("DLT_LINUX_SLL", fpcap::DataLinkType::DLT_LINUX_SLL)
        .value("DLT_LINUX_SLL2", fpcap::DataLinkType::DLT_LINUX_SLL2)
        .finalize();

    // --- WriterFormat enum ---
    py::native_enum<fpcap::WriterFormat>(m, "WriterFormat", "enum.IntEnum")
        .value("AUTO", fpcap::WriterFormat::AUTO)
        .value("PCAP", fpcap::WriterFormat::PCAP)
        .value("PCAPNG", fpcap::WriterFormat::PCAPNG)
        .finalize();

    // --- Packet struct ---
    py::class_<fpcap::Packet>(m, "Packet")
        .def(py::init<>())
        .def_readonly("timestamp_seconds", &fpcap::Packet::timestampSeconds)
        .def_readonly("timestamp_microseconds", &fpcap::Packet::timestampMicroseconds)
        .def_readonly("capture_length", &fpcap::Packet::captureLength)
        .def_readonly("length", &fpcap::Packet::length)
        .def_readonly("data_link_type", &fpcap::Packet::dataLinkType)
        .def_readonly("interface_index", &fpcap::Packet::interfaceIndex)
        .def_property_readonly("data", [](const fpcap::Packet& p) -> py::bytes {
            if (p.data == nullptr || p.captureLength == 0) {
                return py::bytes("", 0);
            }
            return py::bytes(reinterpret_cast<const char*>(p.data), p.captureLength);
        })
        .def("__repr__", [](const fpcap::Packet& p) {
            return "<Packet ts=" + std::to_string(p.timestampSeconds) + "." +
                   std::to_string(p.timestampMicroseconds) +
                   " caplen=" + std::to_string(p.captureLength) +
                   " len=" + std::to_string(p.length) + ">";
        });

    // --- TraceInterface struct ---
    py::class_<fpcap::TraceInterface>(m, "TraceInterface")
        .def(py::init<>())
        .def_readonly("name", &fpcap::TraceInterface::name)
        .def_readonly("description", &fpcap::TraceInterface::description)
        .def_readonly("filter", &fpcap::TraceInterface::filter)
        .def_readonly("os", &fpcap::TraceInterface::os)
        .def_readonly("data_link_type", &fpcap::TraceInterface::dataLinkType)
        .def_readonly("timestamp_resolution", &fpcap::TraceInterface::timestampResolution)
        .def("__repr__", [](const fpcap::TraceInterface& ti) {
            std::string name_str = ti.name.value_or("(none)");
            return "<TraceInterface name='" + name_str +
                   "' dlt=" + std::to_string(ti.dataLinkType) + ">";
        });

    // --- PacketReader class ---
    py::class_<fpcap::PacketReader>(m, "PacketReader")
        .def(py::init<const std::string&, bool>(),
             py::arg("filepath"),
             py::arg("mmap") = true)
        .def("next_packet", [](fpcap::PacketReader& self) -> py::object {
            fpcap::Packet packet{};
            if (self.nextPacket(packet)) {
                return py::cast(packet);
            }
            return py::none();
        })
        .def("is_exhausted", &fpcap::PacketReader::isExhausted)
        .def_property_readonly("filepath", &fpcap::PacketReader::getFilepath)
        .def("get_comment", &fpcap::PacketReader::getComment)
        .def("get_os", &fpcap::PacketReader::getOS)
        .def("get_hardware", &fpcap::PacketReader::getHardware)
        .def("get_user_application", &fpcap::PacketReader::getUserApplication)
        .def("get_trace_interfaces", &fpcap::PacketReader::getTraceInterfaces)
        .def("get_trace_interface", &fpcap::PacketReader::getTraceInterface,
             py::arg("id"))
        .def("__iter__", [](fpcap::PacketReader& self) -> fpcap::PacketReader& {
            return self;
        })
        .def("__next__", [](fpcap::PacketReader& self) -> fpcap::Packet {
            fpcap::Packet packet{};
            if (self.nextPacket(packet)) {
                return packet;
            }
            throw py::stop_iteration();
        });

    // --- Writer class ---
    py::class_<fpcap::Writer>(m, "Writer")
        .def_static("get_writer",
            &fpcap::Writer::getWriter,
            py::arg("filepath"),
            py::arg("append") = false,
            py::arg("format") = fpcap::WriterFormat::AUTO)
        .def("write", &fpcap::Writer::write,
             py::arg("packet"));
}
