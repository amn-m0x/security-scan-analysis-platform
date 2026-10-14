#include <iostream>
#include <stdexcept>
#include <string>
#include <libxml/parser.h>
#include <libxml/tree.h>

bool named(xmlNode* node, const char* name) {
    return node &&
           node->type == XML_ELEMENT_NODE &&
           xmlStrEqual(node->name, BAD_CAST name);
}

std::string attribute(xmlNode* node, const char* key) {
    if (!node) return "";

    xmlChar* value = xmlGetProp(node, BAD_CAST key);
    if (!value) return "";

    std::string result(reinterpret_cast<const char*>(value));
    xmlFree(value);
    return result;
}

xmlNode* child(xmlNode* parent, const char* name) {
    if (!parent) return nullptr;

    for (xmlNode* node = parent->children; node; node = node->next) {
        if (named(node, name)) return node;
    }
    return nullptr;
}

// Escape strings so quotes and control characters produce valid JSON.
std::string quote(const std::string& value) {
    const char* hex = "0123456789abcdef";
    std::string result = "\"";

    for (unsigned char c : value) {
        if (c == '"' || c == '\\') {
            result += '\\';
            result += static_cast<char>(c);
        } else if (c < 0x20) {
            result += "\\u00";
            result += hex[c >> 4];
            result += hex[c & 15];
        } else {
            result += static_cast<char>(c);
        }
    }

    return result + "\"";
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: nmap_parser input.xml\n";
        return 1;
    }

    xmlDoc* document = xmlReadFile(argv[1], nullptr, XML_PARSE_NONET);
    if (!document) {
        std::cerr << "Cannot read XML input.\n";
        return 1;
    }

    try {
        xmlNode* root = xmlDocGetRootElement(document);
        if (!named(root, "nmaprun")) {
            throw std::runtime_error("Expected nmaprun root element.");
        }

        std::string output = "{\"hosts\":[";
        bool firstHost = true;

        for (xmlNode* host = root->children; host; host = host->next) {
            if (!named(host, "host")) continue;

            std::string address;
            for (xmlNode* node = host->children; node; node = node->next) {
                if (!named(node, "address")) continue;

                std::string type = attribute(node, "addrtype");
                if (type == "ipv4" || type == "ipv6") {
                    address = attribute(node, "addr");
                    break;
                }
            }

            if (address.empty()) {
                throw std::runtime_error("Host has no IP address.");
            }

            xmlNode* hostname = child(child(host, "hostnames"), "hostname");

            if (!firstHost) output += ",";
            firstHost = false;

            output += "{\"address\":" + quote(address);
            output += ",\"hostname\":" + quote(attribute(hostname, "name"));
            output += ",\"ports\":[";

            xmlNode* ports = child(host, "ports");
            bool firstPort = true;

            for (xmlNode* port = ports ? ports->children : nullptr;
                 port; port = port->next) {
                if (!named(port, "port")) continue;

                std::string raw = attribute(port, "portid");
                if (raw.empty() ||
                    raw.find_first_not_of("0123456789") != std::string::npos) {
                    throw std::runtime_error("Invalid port number.");
                }

                int number = std::stoi(raw);
                if (number < 0 || number > 65535) {
                    throw std::runtime_error("Port is out of range.");
                }

                xmlNode* state = child(port, "state");
                xmlNode* service = child(port, "service");

                if (!firstPort) output += ",";
                firstPort = false;

                output += "{\"port\":" + std::to_string(number);
                output += ",\"protocol\":" + quote(attribute(port, "protocol"));
                output += ",\"state\":" + quote(attribute(state, "state"));
                output += ",\"service\":" + quote(attribute(service, "name"));
                output += ",\"product\":" + quote(attribute(service, "product"));
                output += ",\"version\":" + quote(attribute(service, "version"));
                output += "}";
            }

            output += "]}";
        }

        output += "]}";
        std::cout << output << '\n';
    } catch (const std::exception& error) {
        std::cerr << "Parse failed: " << error.what() << '\n';
        xmlFreeDoc(document);
        return 1;
    }

    xmlFreeDoc(document);
    return 0;
}
