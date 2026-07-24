#include "MyFuzzCompositionAstBuilder.h"
#include "MyFuzzFrontend.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace myfuzz {
namespace {

constexpr std::size_t kMaxPayloadBytes = 8 * 1024 * 1024;
constexpr std::size_t kMaxJsonDepth = 32;
constexpr std::size_t kMaxContainerItems = 100000;
constexpr std::size_t kMaxStringBytes = 1024 * 1024;

class JsonValue final {
public:
    enum class Kind { Null, Boolean, Number, String, Array, Object };

    Kind kind = Kind::Null;
    bool boolean = false;
    std::string text;
    std::vector<JsonValue> array;
    std::map<std::string, JsonValue> object;
};

class JsonParser final {
    std::string_view m_input;
    std::size_t m_position = 0;
    std::size_t m_items = 0;

    [[noreturn]] void fail(std::string_view reason) const {
        throw std::invalid_argument{"composition_ir.v1:json:" + std::to_string(m_position) + ":"
                                    + std::string{reason}};
    }

    void skipWhitespace() {
        while (m_position < m_input.size()
               && (m_input[m_position] == ' ' || m_input[m_position] == '\t'
                   || m_input[m_position] == '\n' || m_input[m_position] == '\r')) {
            ++m_position;
        }
    }

    char take() {
        if (m_position >= m_input.size()) fail("unexpected-end");
        return m_input[m_position++];
    }

    bool consume(char expected) {
        skipWhitespace();
        if (m_position >= m_input.size() || m_input[m_position] != expected) return false;
        ++m_position;
        return true;
    }

    static unsigned hexValue(char value) {
        if (value >= '0' && value <= '9') return static_cast<unsigned>(value - '0');
        if (value >= 'a' && value <= 'f') return static_cast<unsigned>(value - 'a' + 10);
        if (value >= 'A' && value <= 'F') return static_cast<unsigned>(value - 'A' + 10);
        return UINT_MAX;
    }

    unsigned parseHexQuad() {
        if (m_input.size() - m_position < 4) fail("bad-unicode-escape");
        unsigned value = 0;
        for (int index = 0; index < 4; ++index) {
            const unsigned digit = hexValue(m_input[m_position++]);
            if (digit == UINT_MAX) fail("bad-unicode-escape");
            value = (value << 4U) | digit;
        }
        return value;
    }

    static void appendUtf8(std::string& out, unsigned codepoint) {
        if (codepoint <= 0x7fU) {
            out.push_back(static_cast<char>(codepoint));
        } else if (codepoint <= 0x7ffU) {
            out.push_back(static_cast<char>(0xc0U | (codepoint >> 6U)));
            out.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
        } else if (codepoint <= 0xffffU) {
            out.push_back(static_cast<char>(0xe0U | (codepoint >> 12U)));
            out.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
        } else {
            out.push_back(static_cast<char>(0xf0U | (codepoint >> 18U)));
            out.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
        }
    }

    std::string parseString() {
        skipWhitespace();
        if (take() != '"') fail("string-required");
        std::string out;
        while (m_position < m_input.size()) {
            const unsigned char value = static_cast<unsigned char>(take());
            if (value == '"') return out;
            if (value < 0x20U) fail("control-in-string");
            if (value != '\\') {
                out.push_back(static_cast<char>(value));
            } else {
                const char escape = take();
                switch (escape) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    unsigned codepoint = parseHexQuad();
                    if (codepoint >= 0xd800U && codepoint <= 0xdbffU) {
                        if (m_input.size() - m_position < 6 || m_input[m_position] != '\\'
                            || m_input[m_position + 1] != 'u') {
                            fail("bad-surrogate-pair");
                        }
                        m_position += 2;
                        const unsigned low = parseHexQuad();
                        if (low < 0xdc00U || low > 0xdfffU) fail("bad-surrogate-pair");
                        codepoint = 0x10000U + ((codepoint - 0xd800U) << 10U)
                                    + (low - 0xdc00U);
                    } else if (codepoint >= 0xdc00U && codepoint <= 0xdfffU) {
                        fail("bad-surrogate-pair");
                    }
                    appendUtf8(out, codepoint);
                    break;
                }
                default: fail("bad-string-escape");
                }
            }
            if (out.size() > kMaxStringBytes) fail("string-too-large");
        }
        fail("unterminated-string");
    }

    JsonValue parseNumber() {
        skipWhitespace();
        const std::size_t begin = m_position;
        if (m_position < m_input.size() && m_input[m_position] == '-') ++m_position;
        if (m_position >= m_input.size()) fail("bad-number");
        if (m_input[m_position] == '0') {
            ++m_position;
        } else if (m_input[m_position] >= '1' && m_input[m_position] <= '9') {
            while (m_position < m_input.size() && std::isdigit(
                       static_cast<unsigned char>(m_input[m_position]))) {
                ++m_position;
            }
        } else {
            fail("bad-number");
        }
        if (m_position < m_input.size() && m_input[m_position] == '.') {
            ++m_position;
            const std::size_t digits = m_position;
            while (m_position < m_input.size() && std::isdigit(
                       static_cast<unsigned char>(m_input[m_position]))) {
                ++m_position;
            }
            if (digits == m_position) fail("bad-number");
        }
        if (m_position < m_input.size()
            && (m_input[m_position] == 'e' || m_input[m_position] == 'E')) {
            ++m_position;
            if (m_position < m_input.size()
                && (m_input[m_position] == '+' || m_input[m_position] == '-')) {
                ++m_position;
            }
            const std::size_t digits = m_position;
            while (m_position < m_input.size() && std::isdigit(
                       static_cast<unsigned char>(m_input[m_position]))) {
                ++m_position;
            }
            if (digits == m_position) fail("bad-number");
        }
        JsonValue result;
        result.kind = JsonValue::Kind::Number;
        result.text = std::string{m_input.substr(begin, m_position - begin)};
        return result;
    }

    void accountItem() {
        if (++m_items > kMaxContainerItems) fail("too-many-items");
    }

    JsonValue parseArray(std::size_t depth) {
        JsonValue result;
        result.kind = JsonValue::Kind::Array;
        take();
        skipWhitespace();
        if (consume(']')) return result;
        while (true) {
            accountItem();
            result.array.push_back(parseValue(depth + 1));
            skipWhitespace();
            if (consume(']')) return result;
            if (!consume(',')) fail("array-separator-required");
        }
    }

    JsonValue parseObject(std::size_t depth) {
        JsonValue result;
        result.kind = JsonValue::Kind::Object;
        take();
        skipWhitespace();
        if (consume('}')) return result;
        while (true) {
            accountItem();
            std::string key = parseString();
            if (!consume(':')) fail("object-colon-required");
            auto [it, inserted] = result.object.emplace(std::move(key), parseValue(depth + 1));
            (void)it;
            if (!inserted) fail("duplicate-object-key");
            skipWhitespace();
            if (consume('}')) return result;
            if (!consume(',')) fail("object-separator-required");
        }
    }

    JsonValue parseLiteral(std::string_view literal, JsonValue::Kind kind, bool boolean = false) {
        if (m_input.substr(m_position, literal.size()) != literal) fail("bad-literal");
        m_position += literal.size();
        JsonValue result;
        result.kind = kind;
        result.boolean = boolean;
        return result;
    }

    JsonValue parseValue(std::size_t depth) {
        if (depth > kMaxJsonDepth) fail("nesting-too-deep");
        skipWhitespace();
        if (m_position >= m_input.size()) fail("value-required");
        switch (m_input[m_position]) {
        case '{': return parseObject(depth);
        case '[': return parseArray(depth);
        case '"': {
            JsonValue result;
            result.kind = JsonValue::Kind::String;
            result.text = parseString();
            return result;
        }
        case 't': return parseLiteral("true", JsonValue::Kind::Boolean, true);
        case 'f': return parseLiteral("false", JsonValue::Kind::Boolean, false);
        case 'n': return parseLiteral("null", JsonValue::Kind::Null);
        default: return parseNumber();
        }
    }

public:
    explicit JsonParser(std::string_view input)
        : m_input{input} {}

    JsonValue parse() {
        JsonValue result = parseValue(0);
        skipWhitespace();
        if (m_position != m_input.size()) fail("trailing-data");
        return result;
    }
};

const std::map<std::string, JsonValue>& objectValue(const JsonValue& value,
                                                    std::string_view path) {
    if (value.kind != JsonValue::Kind::Object) {
        throw std::invalid_argument{std::string{path} + ":object-required"};
    }
    return value.object;
}

const std::vector<JsonValue>& arrayValue(const JsonValue& value, std::string_view path) {
    if (value.kind != JsonValue::Kind::Array) {
        throw std::invalid_argument{std::string{path} + ":array-required"};
    }
    return value.array;
}

const JsonValue& requiredMember(const std::map<std::string, JsonValue>& object,
                                std::string_view key, std::string_view path) {
    const auto it = object.find(std::string{key});
    if (it == object.end()) {
        throw std::invalid_argument{std::string{path} + "." + std::string{key} + ":missing"};
    }
    return it->second;
}

const JsonValue* optionalMember(const std::map<std::string, JsonValue>& object,
                                std::string_view key) {
    const auto it = object.find(std::string{key});
    return it == object.end() ? nullptr : &it->second;
}

std::string stringValue(const JsonValue& value, std::string_view path) {
    if (value.kind != JsonValue::Kind::String) {
        throw std::invalid_argument{std::string{path} + ":string-required"};
    }
    return value.text;
}

CompositionId idValue(const JsonValue& value, std::string_view path) {
    if (value.kind != JsonValue::Kind::Number || value.text.empty()
        || value.text.find_first_not_of("0123456789") != std::string::npos) {
        throw std::invalid_argument{std::string{path} + ":positive-integer-required"};
    }
    CompositionId result = 0;
    const char* const begin = value.text.data();
    const char* const end = begin + value.text.size();
    const auto parsed = std::from_chars(begin, end, result);
    if (parsed.ec != std::errc{} || parsed.ptr != end || result == 0) {
        throw std::invalid_argument{std::string{path} + ":positive-integer-required"};
    }
    return result;
}

unsigned widthValue(const JsonValue& value, std::string_view path) {
    const CompositionId width = idValue(value, path);
    if (width > static_cast<CompositionId>(INT_MAX)) {
        throw std::invalid_argument{std::string{path} + ":width-out-of-range"};
    }
    return static_cast<unsigned>(width);
}

bool boolValue(const JsonValue& value, std::string_view path) {
    if (value.kind != JsonValue::Kind::Boolean) {
        throw std::invalid_argument{std::string{path} + ":boolean-required"};
    }
    return value.boolean;
}

template <typename T, typename Key>
void sortBy(std::vector<T>& values, Key key) {
    std::sort(values.begin(), values.end(), [&](const T& lhs, const T& rhs) {
        return key(lhs) < key(rhs);
    });
}

std::string jsonEscape(std::string_view value) {
    std::ostringstream out;
    out << '"';
    static constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char item : value) {
        switch (item) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (item < 0x20U) {
                out << "\\u00" << hex[item >> 4U] << hex[item & 0xfU];
            } else {
                out << static_cast<char>(item);
            }
        }
    }
    out << '"';
    return out.str();
}

void emitIds(std::ostringstream& out, const std::vector<CompositionId>& ids) {
    out << '[';
    for (std::size_t index = 0; index < ids.size(); ++index) {
        if (index) out << ',';
        out << ids[index];
    }
    out << ']';
}

void emitDiagnostics(std::ostringstream& out,
                     const std::vector<CompositionDiagnostic>& diagnostics) {
    out << '[';
    for (std::size_t index = 0; index < diagnostics.size(); ++index) {
        if (index) out << ',';
        const CompositionDiagnostic& item = diagnostics[index];
        out << "{\"code\":" << jsonEscape(item.code) << ",\"message\":"
            << jsonEscape(item.message) << ",\"path\":" << jsonEscape(item.path)
            << ",\"related_ids\":";
        emitIds(out, item.relatedIds);
        out << '}';
    }
    out << ']';
}

}  // namespace

CompositionIr parseCompositionIrJson(std::string_view payload) {
    if (payload.size() > kMaxPayloadBytes) {
        throw std::invalid_argument{"composition_ir.v1:payload-too-large"};
    }
    const JsonValue root = JsonParser{payload}.parse();
    const auto& document = objectValue(root, "composition_ir.v1");
    if (stringValue(requiredMember(document, "schema_version", "composition_ir.v1"),
                    "composition_ir.v1.schema_version")
        != "composition_ir.v1") {
        throw std::invalid_argument{"composition_ir.v1:schema_version:unsupported"};
    }

    CompositionIr result;
    const auto& components
        = arrayValue(requiredMember(document, "components", "composition_ir.v1"), "components");
    for (std::size_t index = 0; index < components.size(); ++index) {
        const auto& item = objectValue(components[index], "components[]");
        result.components.push_back(
            {idValue(requiredMember(item, "id", "components[]"), "components[].id"),
             idValue(requiredMember(item, "module_id", "components[]"),
                     "components[].module_id")});
    }

    const auto& instances
        = arrayValue(requiredMember(document, "instances", "composition_ir.v1"), "instances");
    for (const JsonValue& value : instances) {
        const auto& item = objectValue(value, "instances[]");
        result.instances.push_back(
            {idValue(requiredMember(item, "id", "instances[]"), "instances[].id"),
             idValue(requiredMember(item, "component_id", "instances[]"),
                     "instances[].component_id"),
             idValue(requiredMember(item, "module_id", "instances[]"),
                     "instances[].module_id")});
    }

    const auto& nets
        = arrayValue(requiredMember(document, "nets", "composition_ir.v1"), "nets");
    for (const JsonValue& value : nets) {
        const auto& item = objectValue(value, "nets[]");
        CompositionNet net;
        net.id = idValue(requiredMember(item, "id", "nets[]"), "nets[].id");
        net.sourcePortId = idValue(requiredMember(item, "source_port_id", "nets[]"),
                                   "nets[].source_port_id");
        for (const JsonValue& sink : arrayValue(
                 requiredMember(item, "sink_port_ids", "nets[]"), "nets[].sink_port_ids")) {
            net.sinkPortIds.push_back(idValue(sink, "nets[].sink_port_ids[]"));
        }
        if (const JsonValue* const widthp = optionalMember(item, "width")) {
            net.width = widthValue(*widthp, "nets[].width");
        }
        std::sort(net.sinkPortIds.begin(), net.sinkPortIds.end());
        result.nets.push_back(std::move(net));
    }

    const auto& bindings = arrayValue(
        requiredMember(document, "endpoint_bindings", "composition_ir.v1"),
        "endpoint_bindings");
    for (const JsonValue& value : bindings) {
        const auto& item = objectValue(value, "endpoint_bindings[]");
        CompositionEndpointBinding binding;
        binding.endpointId = idValue(requiredMember(item, "endpoint_id", "endpoint_bindings[]"),
                                     "endpoint_bindings[].endpoint_id");
        binding.componentId
            = idValue(requiredMember(item, "component_id", "endpoint_bindings[]"),
                      "endpoint_bindings[].component_id");
        for (const JsonValue& fieldValue : arrayValue(
                 requiredMember(item, "fields", "endpoint_bindings[]"),
                 "endpoint_bindings[].fields")) {
            const auto& fieldObject
                = objectValue(fieldValue, "endpoint_bindings[].fields[]");
            CompositionEndpointField field;
            field.role = stringValue(
                requiredMember(fieldObject, "field_role", "endpoint_bindings[].fields[]"),
                "endpoint_bindings[].fields[].field_role");
            field.portId = idValue(
                requiredMember(fieldObject, "port_id", "endpoint_bindings[].fields[]"),
                "endpoint_bindings[].fields[].port_id");
            if (const JsonValue* const widthp = optionalMember(fieldObject, "width")) {
                field.width = widthValue(*widthp, "endpoint_bindings[].fields[].width");
            }
            if (const JsonValue* const directionp = optionalMember(fieldObject, "direction")) {
                field.direction
                    = stringValue(*directionp, "endpoint_bindings[].fields[].direction");
            }
            if (const JsonValue* const signedp = optionalMember(fieldObject, "signed")) {
                field.signedness
                    = boolValue(*signedp, "endpoint_bindings[].fields[].signed");
            }
            binding.fields.push_back(std::move(field));
        }
        sortBy(binding.fields, [](const auto& field) {
            return std::make_tuple(field.portId, field.role);
        });
        result.endpointBindings.push_back(std::move(binding));
    }

    const auto& adapters
        = arrayValue(requiredMember(document, "adapters", "composition_ir.v1"), "adapters");
    for (const JsonValue& value : adapters) {
        const auto& item = objectValue(value, "adapters[]");
        CompositionAdapter adapter;
        adapter.edgeId
            = idValue(requiredMember(item, "edge_id", "adapters[]"), "adapters[].edge_id");
        adapter.kind
            = stringValue(requiredMember(item, "kind", "adapters[]"), "adapters[].kind");
        adapter.sourceEndpointId
            = idValue(requiredMember(item, "source_endpoint_id", "adapters[]"),
                      "adapters[].source_endpoint_id");
        adapter.targetEndpointId
            = idValue(requiredMember(item, "target_endpoint_id", "adapters[]"),
                      "adapters[].target_endpoint_id");
        if (const JsonValue* const allowsp = optionalMember(item, "allows_cdc")) {
            adapter.allowsCdc = boolValue(*allowsp, "adapters[].allows_cdc");
        }
        result.adapters.push_back(std::move(adapter));
    }

    auto parseDomains = [&](std::string_view key, std::vector<CompositionDomain>& target) {
        const auto& domains
            = arrayValue(requiredMember(document, key, "composition_ir.v1"), key);
        for (const JsonValue& value : domains) {
            const auto& item = objectValue(value, key);
            const std::string path = std::string{key} + "[]";
            CompositionDomain domain;
            domain.componentId = idValue(requiredMember(item, "component_id", path),
                                         path + ".component_id");
            domain.portId
                = idValue(requiredMember(item, "port_id", path), path + ".port_id");
            domain.domainId
                = idValue(requiredMember(item, "domain_id", path), path + ".domain_id");
            domain.activeLevel = stringValue(requiredMember(item, "active_level", path),
                                             path + ".active_level");
            if (domain.activeLevel != "high" && domain.activeLevel != "low") {
                throw std::invalid_argument{path + ".active_level:invalid"};
            }
            domain.synchronous = boolValue(requiredMember(item, "synchronous", path),
                                           path + ".synchronous");
            target.push_back(std::move(domain));
        }
    };
    parseDomains("clock_domains", result.clockDomains);
    parseDomains("reset_domains", result.resetDomains);

    const auto& externalPorts = arrayValue(
        requiredMember(document, "external_ports", "composition_ir.v1"), "external_ports");
    for (const JsonValue& value : externalPorts) {
        const auto& item = objectValue(value, "external_ports[]");
        CompositionExternalPort external;
        external.portId = idValue(requiredMember(item, "port_id", "external_ports[]"),
                                  "external_ports[].port_id");
        if (const JsonValue* const componentp = optionalMember(item, "component_id")) {
            external.componentId = idValue(*componentp, "external_ports[].component_id");
        }
        external.direction = stringValue(
            requiredMember(item, "direction", "external_ports[]"),
            "external_ports[].direction");
        external.width = widthValue(requiredMember(item, "width", "external_ports[]"),
                                    "external_ports[].width");
        if (const JsonValue* const signedp = optionalMember(item, "signed")) {
            external.signedness = boolValue(*signedp, "external_ports[].signed");
        }
        result.externalPorts.push_back(std::move(external));
    }

    sortBy(result.components, [](const auto& item) { return item.id; });
    sortBy(result.instances, [](const auto& item) { return item.id; });
    sortBy(result.nets, [](const auto& item) { return item.id; });
    sortBy(result.endpointBindings, [](const auto& item) { return item.endpointId; });
    sortBy(result.adapters, [](const auto& item) {
        return std::make_tuple(item.sourceEndpointId, item.targetEndpointId, item.edgeId);
    });
    sortBy(result.clockDomains, [](const auto& item) {
        return std::make_tuple(item.componentId, item.portId, item.domainId);
    });
    sortBy(result.resetDomains, [](const auto& item) {
        return std::make_tuple(item.componentId, item.portId, item.domainId);
    });

    for (CompositionExternalPort& external : result.externalPorts) {
        if (external.componentId) continue;
        for (const CompositionEndpointBinding& binding : result.endpointBindings) {
            const auto found = std::find_if(binding.fields.begin(), binding.fields.end(),
                                            [&](const auto& field) {
                                                return field.portId == external.portId;
                                            });
            if (found != binding.fields.end()) {
                external.componentId = binding.componentId;
                break;
            }
        }
        if (!external.componentId && result.components.size() == 1) {
            external.componentId = result.components.front().id;
        }
    }
    sortBy(result.externalPorts, [](const auto& item) { return item.portId; });
    return result;
}

std::vector<CompositionSourceSymbol> parseCompositionSourceSymbolsJson(
    std::string_view payload) {
    if (payload.size() > kMaxPayloadBytes) {
        throw std::invalid_argument{"source_symbols:payload-too-large"};
    }
    const JsonValue root = JsonParser{payload}.parse();
    const auto& values = arrayValue(root, "source_symbols");
    std::vector<CompositionSourceSymbol> result;
    result.reserve(values.size());
    for (std::size_t index = 0; index < values.size(); ++index) {
        const std::string path = "source_symbols[" + std::to_string(index) + "]";
        const auto& item = objectValue(values[index], path);
        CompositionSourceSymbol symbol;
        symbol.entityId
            = idValue(requiredMember(item, "entity_id", path), path + ".entity_id");
        symbol.kind = stringValue(requiredMember(item, "kind", path), path + ".kind");
        symbol.name = stringValue(requiredMember(item, "name", path), path + ".name");
        symbol.originalName
            = stringValue(requiredMember(item, "original_name", path), path + ".original_name");
        result.push_back(std::move(symbol));
    }
    return result;
}

std::string compositionBuildResultJson(const CompositionBuildResult& result) {
    std::ostringstream out;
    out << "{\"schema_version\":\"composition_build_result.v1\",\"source_text\":"
        << jsonEscape(result.sourceText) << ",\"ast\":{\"module\":";
    if (result.tree) {
        out << "{\"name\":\"composition_top\",\"node_type\":\"AstModule\"}";
    } else {
        out << "null";
    }
    out << ",\"cells\":[";
    for (std::size_t cellIndex = 0; cellIndex < result.ast.cells.size(); ++cellIndex) {
        if (cellIndex) out << ',';
        const CompositionAstCell& cell = result.ast.cells[cellIndex];
        out << "{\"instance_id\":" << cell.instanceId << ",\"module\":"
            << jsonEscape(cell.module) << ",\"name\":" << jsonEscape(cell.name)
            << ",\"node_type\":\"AstCell\",\"pins\":[";
        for (std::size_t pinIndex = 0; pinIndex < cell.pins.size(); ++pinIndex) {
            if (pinIndex) out << ',';
            const CompositionAstPin& pin = cell.pins[pinIndex];
            out << "{\"expression_type\":\"AstVarRef\",\"node_type\":\"AstPin\","
                   "\"port_id\":"
                << pin.portId << ",\"signal\":" << jsonEscape(pin.signal) << '}';
        }
        out << "]}";
    }
    out << "],\"variables\":[";
    for (std::size_t index = 0; index < result.ast.variables.size(); ++index) {
        if (index) out << ',';
        const CompositionAstVariable& variable = result.ast.variables[index];
        out << "{\"declared_width\":";
        if (variable.declaredWidth) {
            out << *variable.declaredWidth;
        } else {
            out << "null";
        }
        out << ",\"kind\":" << jsonEscape(variable.kind) << ",\"name\":"
            << jsonEscape(variable.name) << ",\"node_type\":\"AstVar\",\"stable_id\":"
            << variable.stableId << '}';
    }
    out << "],\"assignments\":[";
    for (std::size_t index = 0; index < result.ast.assignments.size(); ++index) {
        if (index) out << ',';
        const CompositionAstAssignment& assignment = result.ast.assignments[index];
        out << "{\"adapter_id\":" << assignment.adapterId << ",\"lhs\":"
            << jsonEscape(assignment.lhs) << ",\"node_type\":\"AstAssignW\",\"rhs\":"
            << jsonEscape(assignment.rhs) << '}';
    }
    const CompositionAstNodeCounts& counts = result.ast.nodeCounts;
    out << "],\"node_counts\":{\"AstAssignW\":" << counts.wireAssignments
        << ",\"AstCell\":" << counts.cells << ",\"AstModule\":" << counts.modules
        << ",\"AstPin\":" << counts.pins << ",\"AstVar\":" << counts.variables
        << ",\"AstVarRef\":" << counts.variableReferences << "}},\"validation\":{"
        << "\"dtype\":" << (result.validation.dtype ? "true" : "false")
        << ",\"link\":" << (result.validation.link ? "true" : "false")
        << ",\"pin\":" << (result.validation.pin ? "true" : "false")
        << ",\"unknown_width_ports\":";
    emitIds(out, result.validation.unknownWidthPorts);
    out << ",\"width\":" << (result.validation.width ? "true" : "false")
        << "},\"diagnostics\":{\"errors\":";
    emitDiagnostics(out, result.errors);
    out << ",\"warnings\":";
    emitDiagnostics(out, result.warnings);
    out << "}}";
    return out.str();
}

}  // namespace myfuzz

namespace {

char* copyCompositionCString(const std::string& value) {
    char* const out = static_cast<char*>(std::malloc(value.size() + 1));
    if (!out) return nullptr;
    std::memcpy(out, value.c_str(), value.size() + 1);
    return out;
}

}  // namespace

extern "C" char* myfuzz_frontend_composition_json(const char* payload) {
    const std::lock_guard<std::mutex> lock{myfuzz::frontendInvocationMutex()};
    myfuzz::frontendSetLastError({});
    if (!payload) {
        myfuzz::frontendSetLastError("composition payload is null");
        return nullptr;
    }
    const std::size_t size = strnlen(payload, myfuzz::kMaxPayloadBytes + 1);
    if (size > myfuzz::kMaxPayloadBytes) {
        myfuzz::frontendSetLastError("composition_ir.v1:payload-too-large");
        return nullptr;
    }
    try {
        myfuzz::CompositionIr ir = myfuzz::parseCompositionIrJson({payload, size});
        myfuzz::CompositionBuildResult result = myfuzz::buildCompositionAst(ir);
        std::string json = myfuzz::compositionBuildResultJson(result);
        char* const out = copyCompositionCString(json);
        if (!out) myfuzz::frontendSetLastError("unable to allocate composition result");
        return out;
    } catch (const std::exception& ex) {
        myfuzz::frontendSetLastError(ex.what());
        return nullptr;
    } catch (...) {
        myfuzz::frontendSetLastError("unknown composition frontend exception");
        return nullptr;
    }
}

extern "C" char* myfuzz_frontend_composition_with_symbols_json(
    const char* payload, const char* sourceSymbolsPayload) {
    const std::lock_guard<std::mutex> lock{myfuzz::frontendInvocationMutex()};
    myfuzz::frontendSetLastError({});
    if (!payload || !sourceSymbolsPayload) {
        myfuzz::frontendSetLastError("composition or source-symbol payload is null");
        return nullptr;
    }
    const std::size_t size = strnlen(payload, myfuzz::kMaxPayloadBytes + 1);
    const std::size_t sourceSymbolsSize
        = strnlen(sourceSymbolsPayload, myfuzz::kMaxPayloadBytes + 1);
    if (size > myfuzz::kMaxPayloadBytes
        || sourceSymbolsSize > myfuzz::kMaxPayloadBytes) {
        myfuzz::frontendSetLastError("composition emitter payload is too large");
        return nullptr;
    }
    try {
        myfuzz::CompositionIr ir = myfuzz::parseCompositionIrJson({payload, size});
        std::vector<myfuzz::CompositionSourceSymbol> sourceSymbols
            = myfuzz::parseCompositionSourceSymbolsJson(
                {sourceSymbolsPayload, sourceSymbolsSize});
        myfuzz::CompositionBuildResult result
            = myfuzz::buildCompositionAst(ir, sourceSymbols);
        std::string json = myfuzz::compositionBuildResultJson(result);
        char* const out = copyCompositionCString(json);
        if (!out) myfuzz::frontendSetLastError("unable to allocate composition result");
        return out;
    } catch (const std::exception& ex) {
        myfuzz::frontendSetLastError(ex.what());
        return nullptr;
    } catch (...) {
        myfuzz::frontendSetLastError("unknown composition frontend exception");
        return nullptr;
    }
}
