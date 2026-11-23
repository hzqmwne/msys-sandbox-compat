#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include "ProcessSecurityEnvironment_generated.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <vector>

namespace psec_run {
namespace wire = ProcessSecurityEnvironmentLayout;
using Json = nlohmann::json;
using Action = wire::FilterAction;

inline void require(bool condition, const std::string &error) {
    if (!condition)
        throw std::runtime_error(error);
}

inline void fields(const Json &object, const std::string &path,
                   std::initializer_list<std::string_view> allowed) {
    require(object.is_object(), path + " must be an object");
    for (auto field = object.begin(); field != object.end(); ++field)
        require(std::find(allowed.begin(), allowed.end(), field.key()) != allowed.end(),
                "unsupported policy field " + path + "." + field.key());
}

inline Json object_at(const Json &object, const char *key) {
    return object.contains(key) ? object.at(key) : Json::object();
}

inline std::vector<std::string> paths(const Json &object, const char *key) {
    auto values = object.value(key, std::vector<std::string>{});
    for (const auto &path : values)
        require(path.find('\0') == std::string::npos &&
                    std::filesystem::u8path(path).is_absolute(),
                std::string(key) + " requires absolute paths");
    return values;
}

inline Action action(const Json &object, const char *key, const char *path) {
    const auto value = object.value(key, std::string("deny"));
    require(value == "allow" || value == "deny", std::string(path) + " must be allow or deny");
    return value == "allow" ? wire::FilterAction_allow : wire::FilterAction_deny;
}

inline auto destinations(flatbuffers::FlatBufferBuilder &buffer, const Json &items) {
    require(items.is_array() && !items.empty(), "network rule to must be a non-empty array");
    std::vector<flatbuffers::Offset<wire::DestinationRule>> result;
    for (const auto &item : items) {
        fields(item, "network.egress.*.to[]", {"cidr"});
        const auto cidr = item.at("cidr").get<std::string>();
        const auto slash = cidr.find('/');
        require(slash != std::string::npos && cidr.find('\0') == std::string::npos,
                "network destination must be a numeric IPv4 or IPv6 CIDR");
        const auto address = cidr.substr(0, slash);
        unsigned prefix = 0;
        const auto end = cidr.data() + cidr.size();
        const auto parsed = std::from_chars(cidr.data() + slash + 1, end, prefix);
        IN_ADDR ipv4{};
        IN6_ADDR ipv6{};
        const bool valid = (prefix <= 32 && InetPtonA(AF_INET, address.c_str(), &ipv4) == 1) ||
                           (prefix <= 128 && InetPtonA(AF_INET6, address.c_str(), &ipv6) == 1);
        require(parsed.ec == std::errc{} && parsed.ptr == end && valid,
                "invalid network destination CIDR: " + cidr);
        const auto subnet = wire::CreateIpSubnet(buffer, buffer.CreateString(address),
                                                static_cast<uint8_t>(prefix));
        result.push_back(wire::CreateDestinationRule(buffer, subnet));
    }
    return buffer.CreateVector(result);
}

inline auto ports(flatbuffers::FlatBufferBuilder &buffer, const Json &items) {
    require(items.is_array() && !items.empty(), "network rule ports must be a non-empty array");
    std::vector<flatbuffers::Offset<wire::PortRule>> result;
    for (const auto &item : items) {
        fields(item, "network.egress.*.ports[]", {"protocol", "port"});
        const auto name = item.value("protocol", std::string("any"));
        require(name == "tcp" || name == "udp" || name == "any",
                "network port protocol must be tcp, udp, or any");
        const auto protocol = name == "tcp" ? wire::IpProtocol_tcp
                            : name == "udp" ? wire::IpProtocol_udp : wire::IpProtocol_any;
        unsigned port = 0;
        if (item.contains("port")) {
            const auto &field = item.at("port");
            require(field.is_number_integer() && field >= 1 && field <= 65535,
                    "network port must be an integer from 1 through 65535");
            port = field.get<unsigned>();
        }
        result.push_back(wire::CreatePortRule(buffer, protocol, static_cast<uint16_t>(port)));
    }
    return buffer.CreateVector(result);
}

inline auto rules(flatbuffers::FlatBufferBuilder &buffer, const Json &egress, const char *key) {
    using Rules = flatbuffers::Vector<flatbuffers::Offset<wire::EndpointRule>>;
    if (!egress.contains(key))
        return flatbuffers::Offset<Rules>{};
    const auto &items = egress.at(key);
    require(items.is_array(), std::string("network.egress.") + key + " must be an array");
    std::vector<flatbuffers::Offset<wire::EndpointRule>> result;
    for (const auto &item : items) {
        fields(item, "network.egress.*[]", {"to", "ports"});
        result.push_back(wire::CreateEndpointRule(
            buffer, item.contains("to") ? destinations(buffer, item.at("to")) : decltype(destinations(buffer, item)){},
            item.contains("ports") ? ports(buffer, item.at("ports")) : decltype(ports(buffer, item)){}));
    }
    return result.empty() ? flatbuffers::Offset<Rules>{} : buffer.CreateVector(result);
}

inline constexpr uint64_t support_deny = 0x1, support_enumerate = 0x4, support_ingress = 0x8;

struct Policy {
    explicit Policy(const std::filesystem::path &file) {
        std::ifstream input(file);
        require(input.good(), "open policy");
        const auto config = Json::parse(input);
        fields(config, "policy", {"filesystem", "processContainer", "network"});
        const auto fs = object_at(config, "filesystem");
        fields(fs, "filesystem", {"readwritePaths", "readonlyPaths", "deniedPaths"});
        readwrite = paths(fs, "readwritePaths");
        readonly = paths(fs, "readonlyPaths");
        deny = paths(fs, "deniedPaths");
        const auto container = object_at(config, "processContainer");
        fields(container, "processContainer", {"filesystem"});
        const auto container_fs = object_at(container, "filesystem");
        fields(container_fs, "processContainer.filesystem", {"enumeratePaths"});
        enumerate = paths(container_fs, "enumeratePaths");
        const auto network = object_at(config, "network");
        fields(network, "network", {"egress", "ingress"});
        egress = object_at(network, "egress");
        const auto ingress = object_at(network, "ingress");
        fields(egress, "network.egress", {"default", "allow", "deny"});
        fields(ingress, "network.ingress", {"default", "hostLoopback"});
        outbound = action(egress, "default", "network.egress.default");
        inbound = action(ingress, "default", "network.ingress.default");
        loopback = action(ingress, "hostLoopback", "network.ingress.hostLoopback");
    }

    bool needs_ingress() const { return inbound == wire::FilterAction_allow || loopback == wire::FilterAction_allow; }
    bool needs_minor_one() const { return !enumerate.empty() || needs_ingress(); }

    void serialize(flatbuffers::FlatBufferBuilder &buffer, uint16_t minor) const {
        const auto allow = rules(buffer, egress, "allow");
        const auto block = rules(buffer, egress, "deny");
        // Native host-loopback authorization can bypass endpoint filters.
        require(loopback != wire::FilterAction_allow || (allow.IsNull() && block.IsNull()),
                "network.ingress.hostLoopback=allow cannot be combined with egress rules");
        std::string capabilities;
        const auto grant = [&](const char *name) {
            if (!capabilities.empty())
                capabilities += ',';
            capabilities += name;
        };
        if (outbound == wire::FilterAction_allow || !allow.IsNull())
            grant("internetClient");
        if (inbound == wire::FilterAction_allow)
            grant("privateNetworkClientServer");
        if (loopback == wire::FilterAction_allow)
            grant("networkLoopback");
        const auto out = wire::CreateEndpointPolicy(buffer, outbound, allow, block);
        const auto in = needs_ingress() ? wire::CreateIngressPolicy(buffer, inbound, loopback)
                                        : flatbuffers::Offset<wire::IngressPolicy>{};
        const auto peer = loopback == wire::FilterAction_allow ? buffer.CreateString("MXC-Loopback")
                                                    : flatbuffers::Offset<flatbuffers::String>{};
        const auto network = wire::CreateNetworkPolicy(buffer, {}, out, peer, in);
        const auto vector = [&](const auto &values) {
            return values.empty() ? decltype(buffer.CreateVectorOfStrings(values)){}
                                  : buffer.CreateVectorOfStrings(values);
        };
        const wire::SchemaVersion version(1, minor);
        const auto root = wire::CreateProcessSecurityEnvironment(
            buffer, &version, capabilities.empty() ? flatbuffers::Offset<flatbuffers::String>{}
                                                   : buffer.CreateString(capabilities),
            false, 0, vector(readwrite), vector(readonly), vector(deny), network, vector(enumerate));
        wire::FinishProcessSecurityEnvironmentBuffer(buffer, root);
    }

    std::vector<std::string> readwrite, readonly, deny, enumerate;
    Json egress;
    Action outbound, inbound, loopback;
};
} // namespace psec_run
