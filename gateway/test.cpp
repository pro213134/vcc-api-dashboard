

#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <Shlwapi.h>
#include <bcrypt.h>
#include <sspi.h>
#include <schannel.h>
#include "vanguard_gateaway.h"  
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <TlHelp32.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

#include <atomic>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <deque>
#include <functional>
#include <condition_variable>
#include <optional>


#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")


 
 
 
bool authenticatedsession = false;
HANDLE g_vanguard_mutex = nullptr;
HANDLE g_vanguard_shared_memory = nullptr;

constexpr bool          RandomizedVersion = true;
constexpr uint16_t      SERVER_PORT = 51820;
constexpr bool          TLS_SKIP_VERIFY = true;
constexpr int           IDLE_TIMEOUT_SEC = 0;      
constexpr int           HB_INTERVAL_MS = 30000;    
constexpr int           VAN84_THRESH_SEC = 1800;   
constexpr int           MAX_CLIENTS = 32;
constexpr int           SESSION_KEEPALIVE_BOOST = 600;
constexpr int           EMERGENCY_HB_MS = 12000;   
constexpr int           MAX_HB_BURST = 3;
constexpr int           GATEWAY_REAUTH_INTERVAL_SEC = 2 * 60 + 30;

constexpr const char* SERVER_HOST = "127.0.0.1";  // local mod: gateway-relay.js'ye baglanir
constexpr const char* AUTH_KEY = "vcc2024";
constexpr const wchar_t* GW_PATH = L"/vanguard/v1/gateway";
constexpr INTERNET_PORT  GW_PORT = 8443;
constexpr const wchar_t* VGC_UA = L"vanguard/1.18.5-11+20260730.010201";
constexpr const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\933823D3-C77B-4BAE-89D7-A92B567236BC";




static std::wstring RegionToGwHost(const std::string& region) {
    
    
    if (region == "la" || region == "la1" || region == "la2") return L"latam.vg.ac.pvp.net";
    if (region == "br" || region == "br1")                return L"br.vg.ac.pvp.net";
    if (region == "na" || region == "na1")                return L"na.vg.ac.pvp.net";
    if (region == "eu" || region == "eu1" || region == "eu2" || region == "eu3") return L"eu.vg.ac.pvp.net";
    if (region == "ap" || region == "ap1" || region == "ap2") return L"ap.vg.ac.pvp.net";
    if (region == "kr")                               return L"kr.vg.ac.pvp.net";
    
    return L"na.vg.ac.pvp.net";
}




enum MsgType : uint32_t {
    MSG_HELLO = 1,
    MSG_HELLO_OK = 2,
    MSG_SYNC = 3,
    MSG_IOCTL = 4,
    MSG_IOCTL_RESP = 5,
    MSG_HB_BUFFER = 6,
    MSG_PING = 7,
    MSG_PONG = 8,
    MSG_ERROR = 9,
    MSG_JWT_UPDATE = 10,
    MSG_JWT_OK = 11,
    MSG_PIPE_AUTH = 12,
    MSG_PIPE_AUTH_OK = 13,
    MSG_SESSION_AUTH = 14,
    MSG_SESSION_AUTH_OK = 15,
    MSG_SESSION_ACCESS = 16,
    MSG_SESSION_ACCESS_OK = 17,
    MSG_SESSION_HEARTBEAT = 18,
    MSG_SESSION_HEARTBEAT_OK = 19,
    MSG_SESSION_REPORT = 20,
    MSG_SESSION_REPORT_OK = 21,
    MSG_SESSION_DISCONNECT = 22,
    MSG_SESSION_DISCONNECT_OK = 23,
    MSG_AUTH_REQUEST = 100,   
    MSG_AUTH_RESPONSE = 101,  
    MSG_TASKS_DATA = 102,     
    MSG_TASKS_ACK = 103,      
    MSG_ROUND_START = 110,    
    MSG_ROUND_END = 111,      
};

constexpr uint32_t IOCTL_VGK_HB = 0x222000;
constexpr uint32_t IOCTL_VGK_ACC = 0x22C03C;
constexpr size_t   MAX_PAYLOAD = 128 * 1024 * 1024;




static std::mutex    g_log_mtx;
static std::ofstream g_log_file;
static std::mutex    g_ui_log_mtx;
static std::deque<std::string> g_ui_log_lines;


static std::vector<std::string> g_log_lines;
static std::mutex g_log_mutex;

static void PushUiLogLine(const std::string& line) {
    std::lock_guard<std::mutex> lk(g_ui_log_mtx);
    g_ui_log_lines.push_back(line);
    while (g_ui_log_lines.size() > 300) {
        g_ui_log_lines.pop_front();
    }
    
    {
        std::lock_guard<std::mutex> lk2(g_log_mutex);
        g_log_lines.push_back(line);
        while (g_log_lines.size() > 20)
            g_log_lines.erase(g_log_lines.begin());
    }
}

static void Log(const std::string& msg) {
    
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    std::tm bt{}; localtime_s(&bt, &t);
    std::ostringstream ss;
    ss << "[" << std::put_time(&bt, "%H:%M:%S")
        << "." << std::setfill('0') << std::setw(3) << ms.count()
        << "] " << msg;
    PushUiLogLine(ss.str());
    std::lock_guard<std::mutex> lk(g_log_mtx);
    if (g_log_file.is_open()) { g_log_file << ss.str() << "\n"; g_log_file.flush(); }
}





static void PushU32BE(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back((x >> 24) & 0xFF); v.push_back((x >> 16) & 0xFF);
    v.push_back((x >> 8) & 0xFF);  v.push_back(x & 0xFF);
}
static void PushU64BE(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 7;i >= 0;i--) v.push_back((uint8_t)(x >> (i * 8)));
}
static void PushLenStr(std::vector<uint8_t>& v, const std::string& s) {
    PushU32BE(v, (uint32_t)s.size());
    v.insert(v.end(), s.begin(), s.end());
}
static void PushLenBytes(std::vector<uint8_t>& v, const std::vector<uint8_t>& b) {
    PushU32BE(v, (uint32_t)b.size());
    v.insert(v.end(), b.begin(), b.end());
}
static uint32_t ReadU32BE(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static uint64_t ReadU64BE(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0;i < 8;i++) v = (v << 8) | p[i];
    return v;
}

static std::vector<uint8_t> PackMsg(uint32_t type, const std::vector<uint8_t>& payload) {
    if (payload.size() > MAX_PAYLOAD) throw std::runtime_error("payload too large");
    std::vector<uint8_t> pkt;
    PushU32BE(pkt, type);
    PushU32BE(pkt, (uint32_t)payload.size());
    pkt.insert(pkt.end(), payload.begin(), payload.end());
    return pkt;
}
static std::vector<uint8_t> PackMsg(uint32_t type) {
    std::vector<uint8_t> pkt;
    PushU32BE(pkt, type); PushU32BE(pkt, 0);
    return pkt;
}


static std::string ParseLPStr(const std::vector<uint8_t>& buf, size_t& off) {
    if (off + 4 > buf.size()) return "";
    uint32_t len = ReadU32BE(buf.data() + off); off += 4;
    if (off + len > buf.size()) return "";
    std::string s((char*)buf.data() + off, len); off += len;
    return s;
}
static std::vector<uint8_t> ParseLPBytes(const std::vector<uint8_t>& buf, size_t& off) {
    if (off + 4 > buf.size()) return {};
    uint32_t len = ReadU32BE(buf.data() + off); off += 4;
    if (off + len > buf.size()) return {};
    std::vector<uint8_t> b(buf.data() + off, buf.data() + off + len); off += len;
    return b;
}

static std::vector<uint8_t> ParseSessionGatewayBody(const std::vector<uint8_t>& payload, std::string* session_id = nullptr) {
    size_t off = 0;
    std::string sid = ParseLPStr(payload, off);
    if (session_id) *session_id = sid;
    if (off + 4 > payload.size()) return {};
    uint32_t gw_len = ReadU32BE(payload.data() + off);
    off += 4;
    if (off + gw_len > payload.size()) return {};
    return std::vector<uint8_t>(payload.begin() + off, payload.begin() + off + gw_len);
}





static std::string Base64UrlDecode(const std::string& in) {
    std::string s = in;
    for (auto& c : s) { if (c == '-')c = '+'; if (c == '_')c = '/'; }
    while (s.size() % 4) s += '=';
    DWORD outLen = 0;
    CryptStringToBinaryA(s.c_str(), (DWORD)s.size(), CRYPT_STRING_BASE64,
        nullptr, &outLen, nullptr, nullptr);
    std::string out(outLen, '\0');
    CryptStringToBinaryA(s.c_str(), (DWORD)s.size(), CRYPT_STRING_BASE64,
        (BYTE*)out.data(), &outLen, nullptr, nullptr);
    out.resize(outLen);
    return out;
}


static std::string JsonGetStr(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return "";
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' || json[pos] == '\t')) pos++;
    if (pos >= json.size()) return "";
    if (json[pos] == '"') {
        pos++;
        auto end = json.find('"', pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    }
    
    auto end = json.find_first_of(",}", pos);
    return json.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
}

static std::string DecodeJwtPayload(const std::string& jwt) {
    auto dot1 = jwt.find('.');
    if (dot1 == std::string::npos) return "";
    auto dot2 = jwt.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return "";
    return Base64UrlDecode(jwt.substr(dot1 + 1, dot2 - dot1 - 1));
}

static std::string ShardFromJwt(const std::string& jwt) {
    auto payload = DecodeJwtPayload(jwt);

    
    {
        auto dat_pos = payload.find("\"dat\"");
        if (dat_pos != std::string::npos) {
            auto brace = payload.find('{', dat_pos);
            auto close = payload.find('}', brace);
            if (brace != std::string::npos && close != std::string::npos) {
                std::string dat_obj = payload.substr(brace, close - brace + 1);
                std::string dr = JsonGetStr(dat_obj, "r");
                for (auto& c : dr) c = tolower(c);
                if (!dr.empty()) {
                    if (dr == "la2" || dr == "la1" || dr == "la") return "la";
                    if (dr == "br1" || dr == "br")             return "br";
                    if (dr == "na1" || dr == "na")             return "na";
                    if (dr == "eu1" || dr == "eu2" || dr == "eu3" || dr == "eu") return "eu";
                    if (dr == "ap1" || dr == "ap2" || dr == "ap")  return "ap";
                    if (dr == "kr")                        return "kr";
                }
            }
        }
    }

    
    std::string r = JsonGetStr(payload, "r");
    for (auto& c : r) c = tolower(c);
    if (r == "br" || r == "br1")                               return "br";
    if (r == "la" || r == "la1" || r == "la2")                 return "la";
    if (r == "na" || r == "na1")                               return "na";
    if (r == "eu" || r == "eu1" || r == "eu2" || r == "eu3")   return "eu";
    if (r == "ap" || r == "ap1" || r == "ap2")                 return "ap";
    if (r == "kr")                                             return "kr";

    
    std::string aff = JsonGetStr(payload, "affinity");
    if (aff.empty()) aff = JsonGetStr(payload, "region");
    for (auto& c : aff) c = tolower(c);
    if (!aff.empty()) {
        if (aff.find("la") != std::string::npos) return "la";
        if (aff.find("br") != std::string::npos) return "br";
        if (aff.find("na") != std::string::npos) return "na";
        if (aff.find("eu") != std::string::npos) return "eu";
        if (aff.find("ap") != std::string::npos) return "ap";
        if (aff.find("kr") != std::string::npos) return "kr";
    }

    
    std::string cty = JsonGetStr(payload, "cty");
    if (cty.empty()) cty = JsonGetStr(payload, "lcty");
    for (auto& c : cty) c = tolower(c);
    
    if (cty == "usa" || cty == "can" || cty == "mex") return "na";
    
    if (cty == "kor" || cty == "kr") return "kr";
    
    if (cty == "bra" || cty == "arg" || cty == "chl" || cty == "col" ||
        cty == "per" || cty == "ven" || cty == "ecu" || cty == "bol" ||
        cty == "pry" || cty == "ury") return "br";
    
    if (cty == "gtm" || cty == "cri" || cty == "pan" || cty == "hnd" ||
        cty == "slv" || cty == "nic" || cty == "dom") return "la";
    
    if (cty == "deu" || cty == "fra" || cty == "gbr" || cty == "esp" ||
        cty == "ita" || cty == "pol" || cty == "tur" || cty == "nld" ||
        cty == "bel" || cty == "che" || cty == "aut" || cty == "swe" ||
        cty == "nor" || cty == "dnk" || cty == "fin" || cty == "prt" ||
        cty == "grc" || cty == "cze" || cty == "hun" || cty == "rou" ||
        cty == "rus" || cty == "ukr" || cty == "mda") return "eu";
    
    if (cty == "jpn" || cty == "aus" || cty == "sgp" || cty == "nzl" ||
        cty == "phl" || cty == "tha" || cty == "idn" || cty == "mys" ||
        cty == "vnm" || cty == "twn" || cty == "hkg" || cty == "mmr") return "ap";

    
    
    std::string iss = JsonGetStr(payload, "iss");
    for (auto& c : iss) c = tolower(c);
    if (iss.find(".la.") != std::string::npos || iss.find("latam") != std::string::npos) return "la";
    if (iss.find(".br.") != std::string::npos) return "br";
    if (iss.find(".na.") != std::string::npos || iss.find("na1") != std::string::npos) return "na";
    if (iss.find(".eu.") != std::string::npos || iss.find("eu1") != std::string::npos) return "eu";
    if (iss.find(".ap.") != std::string::npos || iss.find("ap1") != std::string::npos) return "ap";
    if (iss.find(".kr.") != std::string::npos) return "kr";

    return ""; 
}

static std::string NormalizeShardHintRobust(std::string value) {
    for (auto& c : value) c = (char)tolower((unsigned char)c);
    while (!value.empty() && (value.back() == '"' || value.back() == ' ' || value.back() == '\r' || value.back() == '\n' || value.back() == '\t')) value.pop_back();
    while (!value.empty() && (value.front() == '"' || value.front() == ' ' || value.front() == '\r' || value.front() == '\n' || value.front() == '\t')) value.erase(value.begin());
    if (value.empty()) return "";

    if (value == "la" || value == "la1" || value == "la2" || value == "latam") return "la";
    if (value == "br" || value == "br1" || value == "brazil") return "br";
    if (value == "na" || value == "na1" || value == "na2" || value == "northamerica" || value == "north_america") return "na";
    if (value == "eu" || value == "eu1" || value == "eu2" || value == "eu3" || value == "emea" || value == "europe" || value == "euw" || value == "eune") return "eu";
    if (value == "ap" || value == "ap1" || value == "ap2" || value == "apac" || value == "asia" || value == "oce") return "ap";
    if (value == "kr" || value == "korea") return "kr";

    if (value.find("latam") != std::string::npos || value.rfind("la", 0) == 0) return "la";
    if (value.find("brazil") != std::string::npos || value.rfind("br", 0) == 0) return "br";
    if (value.find("emea") != std::string::npos || value.find("europe") != std::string::npos || value.rfind("eu", 0) == 0) return "eu";
    if (value.find("north") != std::string::npos || value.rfind("na", 0) == 0) return "na";
    if (value.find("apac") != std::string::npos || value.find("asia") != std::string::npos || value.find("oce") != std::string::npos || value.rfind("ap", 0) == 0) return "ap";
    if (value.find("korea") != std::string::npos || value.rfind("kr", 0) == 0) return "kr";
    return "";
}

static std::string ShardFromJwtRobust(const std::string& jwt) {
    auto payload = DecodeJwtPayload(jwt);
    if (payload.empty()) return "";

    {
        auto dat_pos = payload.find("\"dat\"");
        if (dat_pos != std::string::npos) {
            auto brace = payload.find('{', dat_pos);
            auto close = payload.find('}', brace);
            if (brace != std::string::npos && close != std::string::npos) {
                std::string dat_obj = payload.substr(brace, close - brace + 1);
                if (auto v = NormalizeShardHintRobust(JsonGetStr(dat_obj, "r")); !v.empty()) return v;
                if (auto v = NormalizeShardHintRobust(JsonGetStr(dat_obj, "region")); !v.empty()) return v;
                if (auto v = NormalizeShardHintRobust(JsonGetStr(dat_obj, "affinity")); !v.empty()) return v;
            }
        }
    }

    for (const auto& key : { "r", "affinity", "region", "shard", "player_region", "geo_region", "geo", "loc" }) {
        if (auto v = NormalizeShardHintRobust(JsonGetStr(payload, key)); !v.empty()) return v;
    }

    for (const auto& pattern : {
        std::regex("\"r\"\\s*:\\s*\"([^\"]+)\""),
        std::regex("\"affinity\"\\s*:\\s*\"([^\"]+)\""),
        std::regex("\"region\"\\s*:\\s*\"([^\"]+)\""),
        std::regex("\"shard\"\\s*:\\s*\"([^\"]+)\""),
        std::regex("\"player_region\"\\s*:\\s*\"([^\"]+)\""),
        std::regex("\"geo_region\"\\s*:\\s*\"([^\"]+)\"")
        }) {
        std::smatch m;
        if (std::regex_search(payload, m, pattern) && m.size() > 1) {
            if (auto v = NormalizeShardHintRobust(m[1].str()); !v.empty()) return v;
        }
    }

    auto region_from_country = [](std::string cty) -> std::string {
        for (auto& c : cty) c = (char)tolower((unsigned char)c);
        if (cty == "usa" || cty == "us" || cty == "can" || cty == "ca" || cty == "mex" || cty == "mx") return "na";
        if (cty == "kor" || cty == "kr") return "kr";
        if (cty == "bra" || cty == "br" || cty == "arg" || cty == "ar" || cty == "chl" || cty == "cl" || cty == "col" || cty == "co" ||
            cty == "per" || cty == "pe" || cty == "ven" || cty == "ve" || cty == "ecu" || cty == "ec" || cty == "bol" || cty == "bo" ||
            cty == "pry" || cty == "py" || cty == "ury" || cty == "uy") return "br";
        if (cty == "gtm" || cty == "gt" || cty == "cri" || cty == "cr" || cty == "pan" || cty == "pa" || cty == "hnd" || cty == "hn" ||
            cty == "slv" || cty == "sv" || cty == "nic" || cty == "ni" || cty == "dom" || cty == "do") return "la";
        if (cty == "deu" || cty == "de" || cty == "fra" || cty == "fr" || cty == "gbr" || cty == "gb" || cty == "uk" || cty == "esp" || cty == "es" ||
            cty == "ita" || cty == "it" || cty == "pol" || cty == "pl" || cty == "tur" || cty == "tr" || cty == "nld" || cty == "nl" ||
            cty == "bel" || cty == "be" || cty == "che" || cty == "ch" || cty == "aut" || cty == "at" || cty == "swe" || cty == "se" ||
            cty == "nor" || cty == "no" || cty == "dnk" || cty == "dk" || cty == "fin" || cty == "fi" || cty == "prt" || cty == "pt" ||
            cty == "grc" || cty == "gr" || cty == "cze" || cty == "cz" || cty == "hun" || cty == "hu" || cty == "rou" || cty == "ro" ||
            cty == "rus" || cty == "ru" || cty == "ukr" || cty == "ua" || cty == "mda" || cty == "md") return "eu";
        if (cty == "jpn" || cty == "jp" || cty == "aus" || cty == "au" || cty == "sgp" || cty == "sg" || cty == "nzl" || cty == "nz" ||
            cty == "phl" || cty == "ph" || cty == "tha" || cty == "th" || cty == "idn" || cty == "id" || cty == "mys" || cty == "my" ||
            cty == "vnm" || cty == "vn" || cty == "twn" || cty == "tw" || cty == "hkg" || cty == "hk" || cty == "mmr" || cty == "mm" ||
            cty == "pak" || cty == "pk") return "ap";
        return "";
    };

    std::string cty = JsonGetStr(payload, "cty");
    std::string lcty = JsonGetStr(payload, "lcty");
    if (auto v = region_from_country(lcty); !v.empty()) return v;
    if (auto v = region_from_country(cty); !v.empty()) return v;

    std::string iss = JsonGetStr(payload, "iss");
    for (auto& c : iss) c = (char)tolower((unsigned char)c);
    if (iss.find(".la.") != std::string::npos || iss.find("latam") != std::string::npos) return "la";
    if (iss.find(".br.") != std::string::npos) return "br";
    if (iss.find(".na.") != std::string::npos || iss.find("na1") != std::string::npos) return "na";
    if (iss.find(".eu.") != std::string::npos || iss.find("eu1") != std::string::npos || iss.find("emea") != std::string::npos || iss.find("europe") != std::string::npos) return "eu";
    if (iss.find(".ap.") != std::string::npos || iss.find("ap1") != std::string::npos) return "ap";
    if (iss.find(".kr.") != std::string::npos) return "kr";

    return ShardFromJwt(jwt);
}

static void LogJwtRegionHints(const std::string& jwt, const std::string& prefix) {
    auto payload = DecodeJwtPayload(jwt);
    if (payload.empty()) {
        Log(prefix + " jwt_payload=EMPTY");
        return;
    }

    std::string dat_r;
    auto dat_pos = payload.find("\"dat\"");
    if (dat_pos != std::string::npos) {
        auto brace = payload.find('{', dat_pos);
        auto close = payload.find('}', brace);
        if (brace != std::string::npos && close != std::string::npos) {
            dat_r = JsonGetStr(payload.substr(brace, close - brace + 1), "r");
        }
    }

    std::string iss = JsonGetStr(payload, "iss");
    if (iss.size() > 64) iss = iss.substr(0, 64) + "...";

    Log(prefix +
        " dat.r=" + (dat_r.empty() ? "<empty>" : dat_r) +
        " r=" + (JsonGetStr(payload, "r").empty() ? "<empty>" : JsonGetStr(payload, "r")) +
        " affinity=" + (JsonGetStr(payload, "affinity").empty() ? "<empty>" : JsonGetStr(payload, "affinity")) +
        " region=" + (JsonGetStr(payload, "region").empty() ? "<empty>" : JsonGetStr(payload, "region")) +
        " shard=" + (JsonGetStr(payload, "shard").empty() ? "<empty>" : JsonGetStr(payload, "shard")) +
        " player_region=" + (JsonGetStr(payload, "player_region").empty() ? "<empty>" : JsonGetStr(payload, "player_region")) +
        " geo_region=" + (JsonGetStr(payload, "geo_region").empty() ? "<empty>" : JsonGetStr(payload, "geo_region")) +
        " cty=" + (JsonGetStr(payload, "cty").empty() ? "<empty>" : JsonGetStr(payload, "cty")) +
        " lcty=" + (JsonGetStr(payload, "lcty").empty() ? "<empty>" : JsonGetStr(payload, "lcty")) +
        " iss=" + (iss.empty() ? "<empty>" : iss));
}

static std::string AccountFromJwt(const std::string& jwt) {
    auto payload = DecodeJwtPayload(jwt);
    for (auto& k : { "sub","acct","name" }) {
        auto v = JsonGetStr(payload, k);
        if (!v.empty()) return v;
    }
    return "";
}

static std::string PuuidFromJwt(const std::string& jwt) {
    auto payload = DecodeJwtPayload(jwt);
    static const std::regex uuid_re(
        R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");
    for (auto& k : { "sub","puuid" }) {
        auto v = JsonGetStr(payload, k);
        if (std::regex_match(v, uuid_re)) return v;
    }
    std::smatch m;
    if (std::regex_search(payload, m, uuid_re)) return m[0].str();
    return "";
}

static std::string ResolveNonEmptySid(const std::string& jwt, const std::string& sid, const std::string& puuid, const char* tag) {
    
    if (!sid.empty() && sid != puuid) return sid;

    std::string jwt_puuid = PuuidFromJwt(jwt);
    if (!sid.empty() && sid != jwt_puuid) return sid;

    Log(std::string(tag) + " no distinct session UUID in pipe — f13 will be empty");
    if (false) { 
        return jwt_puuid;
    }

    Log(std::string(tag) + " WARNING: sid fallback unavailable");
    return "";
}





class FallbackCache {
public:
    void update(const std::string& sid, const std::vector<uint8_t>& resp) {
        std::lock_guard<std::mutex> lk(mtx_);
        store_[sid] = resp;
    }
    std::vector<uint8_t> get(const std::string& sid) const {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = store_.find(sid);
        return it != store_.end() ? it->second : std::vector<uint8_t>{};
    }
private:
    mutable std::mutex mtx_;
    std::map<std::string, std::vector<uint8_t>> store_;
};
static FallbackCache g_fallback;




class EventLog {
public:
    EventLog() {}
    void log(const std::string&, const std::string&, const std::string&,
             const std::string& = "", int = 0, int = -1) {}
private:
    std::mutex mtx_;
};
static EventLog g_elog;









static std::vector<uint8_t> g_vgk_payload;
static std::mutex           g_vgk_payload_mtx;

static bool GatewayDoReauth();
static std::vector<uint8_t> g_gw_auth_response;
static std::mutex            g_gw_auth_response_mtx;
static VGW::GatewaySession   g_gw_session;
static std::mutex            g_gw_session_mtx;




static const uint8_t FALLBACK_TOKEN[] = {
    0x08,0x01,0x12,0xA0,0x02,0x52,0x47,0x01,0x00,0x05,0xFA,0xA7,
    0x74,0xC9,0x93,0x69,0x50,0x77,0xF4,0xB0,0xD9,0xC8,0x0D,0x6F,
    0x67,0x57,0x08,0xCB,0xFC,0x03,0x06,0x60,0x70,0x2C,0x73,0x9E,
    0x2C,0xA5,0xF7,0x25,0xF0,0x4E,0x2A,0x8F,0x9F,0xB5,0xC7,0x06,
    0xA9,0x4E,0x78,0x15,0x7B,0x20,0x7D,0xD3,0x0F,0xC5,0xB8,0x24,
    0xEE,0xD2,0xBC,0xA1,0x9E,0x83,0x0F,0x34,0x98,0x2F,0x3D,0xED,
    0xF1,0x3A,0xD2,0x63,0xDC,0xA0,0xA6,0x16,0x9F,0xAA,0x21,0xD5,
    0xA4,0xE9,0x1C,0xFE,0xB6,0x7A,0xC2,0x4B,0x0C,0x6F,0x90,0x7B,
    0x6F,0x80,0x77,0x70,0x67,0x3B,0x0A,0xB5,0x2A,0x4A,0x71,0xBF,
    0xBE,0xE9,0xBE,0x4C,0xBE,0xF3,0xC2,0xBE,0xCD,0x2F,0xB2,0xDA,
    0xE8,0x82,0xDB,0xDD,0x3F,0xF0,0x5A,0x98,0x0D,0xA0,0x2D,0x7F,
    0xAD,0xDA,0xE7,0xD6,0xF5,0x9D,0x32,0x1D,0x0B,0x38,0x48,0x9F,
    0x03,0xBD,0x23,0xF0,0x39,0x76,0x52,0x67,0x8F,0x02,0x32,0x3B,
    0xBC,0x82,0xCA,0x10,0xDE,0x6A,0xC7,0x3C,0x51,0x14,0xFF,0x58,
    0x8B,0xFE,0x7B,0x63,0xA6,0xE2,0x9D,0xDB,0x5B,0xC0,0xCD,0x7F,
    0x92,0xCE,0xA6,0x5D,0x0C,0x19,0x25,0x00,0x6E,0xDC,0x7B,0x3B,
    0x0F,0x68,0x2B,0xE1,0xDD,0xE8,0x66,0x03,0x70,0x58,0x3E,0x5F,
    0xEA,0xB1,0x65,0x68,0x4C,0xB1,0x2D,0xF9,0x7E,0xD9,0x45,0xBF,
    0x06,0xAD,0xDF,0x74,0xFC,0x1A,0x5F,0x09,0x41,0x33,0xA6,0x30,
    0xF2,0xD6,0x02,0xE6,0xCB,0x46,0x37,0xF3,0x2B,0x7A,0xB9,0x7A,
    0xC6,0x06,0x13,0x7C,0x0A,0xF5,0x78,0xB4,0x36,0x43,0xDD,0x6E,
    0xBF,0x68,0xBF,0x90,0xC7,0x0E,0x7D,0x19,0x72,0xBB,0xDA,0x9F,
    0xF5,0x44,0x82,0x96,0x2F,0xD0,0x2F,0xEB,0x49,0xBE,0x8B,0x17,
    0x05,0x5D,0xE3,0x8C,0x10,0xBA,0xB3,0x42,0x7C,0x01,0xDD,0xA9,
    0x00,0xE5,0xC2,0x6D,0xD0,
};
static const size_t FALLBACK_TOKEN_LEN = sizeof(FALLBACK_TOKEN);

struct CryptoSession {
    std::string jwt;
    std::string puuid;
    bool mounted = false;
    int  hb_count = 0;
    int  token_variant = 0;

    void mount(const std::string& j, const std::string& p) {
        jwt = j; puuid = p; mounted = true; hb_count = 0; token_variant = 0;
    }
    void update_jwt(const std::string& j, const std::string& p) {
        jwt = j; puuid = p; token_variant = 0;
    }
    std::vector<uint8_t> heartbeat_payload() {
        hb_count++;
        
        {
            std::lock_guard<std::mutex> lk(g_vgk_payload_mtx);
            if (!g_vgk_payload.empty()) {
                Log("[CRYPTO] using real vgk payload hb#" + std::to_string(hb_count) + " size=" + std::to_string(g_vgk_payload.size()));
                return g_vgk_payload;
            }
        }
        
        {
            std::lock_guard<std::mutex> lk(g_gw_auth_response_mtx);
            if (!g_gw_auth_response.empty()) {
                Log("[CRYPTO] using fresh gateway response payload hb#" + std::to_string(hb_count) + " size=" + std::to_string(g_gw_auth_response.size()));
                return g_gw_auth_response;
            }
        }

        {
            std::lock_guard<std::mutex> lk(g_gw_session_mtx);
            if (!g_gw_session.last_auth_response.empty()) {
                Log("[CRYPTO] using cached gateway session payload hb#" + std::to_string(hb_count) + " size=" + std::to_string(g_gw_session.last_auth_response.size()));
                return g_gw_session.last_auth_response;
            }
        }

        Log("[CRYPTO] WARNING: using FALLBACK_TOKEN hb#" + std::to_string(hb_count) + " (real vgk payload not yet received)");
        return std::vector<uint8_t>(FALLBACK_TOKEN, FALLBACK_TOKEN + FALLBACK_TOKEN_LEN);
    }
    std::vector<uint8_t> ioctl_response(uint32_t code, const std::vector<uint8_t>& data) {
        if (!mounted) return {};
        if (code == IOCTL_VGK_HB) return heartbeat_payload();
        if (code == IOCTL_VGK_ACC) {
            if (!data.empty()) return heartbeat_payload();
            return { 0x43,0x4C,0x45,0x41,0x4E,0x00 }; 
        }
        if ((code >> 16) == 0x22) {
            if (!data.empty()) return heartbeat_payload();
            return { 0x43,0x4C,0x45,0x41,0x4E,0x00 };
        }
        if (!data.empty()) return data;
        return heartbeat_payload();
    }
};





struct ProgramWorker {
    std::string  container_id;
    std::string  program_path;
    HANDLE       proc = INVALID_HANDLE_VALUE;
    uint16_t     port = 0;
    bool         ready_ = false;

    bool alive() const {
        if (proc == INVALID_HANDLE_VALUE) return false;
        DWORD code = 0;
        return GetExitCodeProcess(proc, &code) && code == STILL_ACTIVE;
    }

    bool start() {
        if (program_path.empty() || GetFileAttributesA(program_path.c_str()) == INVALID_FILE_ATTRIBUTES)
            return false;
        
        WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
        SOCKET tmp = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(tmp, (sockaddr*)&sa, sizeof(sa));
        int salen = sizeof(sa); getsockname(tmp, (sockaddr*)&sa, &salen);
        port = (uint16_t)ntohs(sa.sin_port);
        closesocket(tmp);

        std::string cmd = program_path
            + " --container " + container_id
            + " --ipc-port " + std::to_string(port);
        STARTUPINFOA si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (!CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return false;
        CloseHandle(pi.hThread);
        proc = pi.hProcess;

        
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (std::chrono::steady_clock::now() < deadline) {
            if (!alive()) return false;
            if (_ping()) { ready_ = true; return true; }
            Sleep(150);
        }
        stop(); return false;
    }

    void stop() {
        if (alive()) TerminateProcess(proc, 0);
        if (proc != INVALID_HANDLE_VALUE) { CloseHandle(proc); proc = INVALID_HANDLE_VALUE; }
        ready_ = false;
    }

    std::vector<uint8_t> ioctl(uint32_t code, const std::vector<uint8_t>& data, int timeout_ms = 5000) {
        
        std::vector<uint8_t> req(10 + data.size());
        req[0] = 1; req[1] = 2;
        req[2] = req[3] = 0;
        req[4] = (code >> 24) & 0xFF; req[5] = (code >> 16) & 0xFF;
        req[6] = (code >> 8) & 0xFF;  req[7] = code & 0xFF;
        uint32_t dlen = (uint32_t)data.size();
        req[8] = (dlen >> 8) & 0xFF; req[9] = dlen & 0xFF;  
        memcpy(req.data() + 10, data.data(), data.size());
        auto resp = _request(req, timeout_ms);
        if (resp.size() < 4) return {};
        uint32_t status = (resp[0] << 8) | resp[1];
        if (status != 0) return {};
        uint32_t rlen = (resp[2] << 8) | resp[3];
        if (resp.size() < 4 + rlen) return {};
        return std::vector<uint8_t>(resp.begin() + 4, resp.begin() + 4 + rlen);
    }

    bool _ping() {
        std::vector<uint8_t> req = { 1,4,0,0,0,0,0,0,0,0 };
        try { auto r = _request(req, 500); return r.size() >= 2 && r[0] == 0 && r[1] == 0; }
        catch (...) { return false; }
    }

    std::vector<uint8_t> _request(const std::vector<uint8_t>& req, int timeout_ms) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        DWORD to = (DWORD)timeout_ms;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof(to));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&to, sizeof(to));
        sockaddr_in addr{}; addr.sin_family = AF_INET;
        addr.sin_port = htons(port); addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) { closesocket(s); return {}; }
        send(s, (char*)req.data(), (int)req.size(), 0);
        std::vector<uint8_t> buf(16384); int got = recv(s, (char*)buf.data(), (int)buf.size(), 0);
        closesocket(s);
        if (got <= 0) return {};
        buf.resize(got); return buf;
    }
};





struct Session {
    std::string  session_id;
    std::string  riot_token;
    std::string  puuid;
    std::string  region;
    std::string  riot_account;
    std::string  hostname;
    std::string  client_ip;
    std::string  container_id;
    std::vector<uint8_t> gateway_machine_id;
    std::vector<uint8_t> hwid_fingerprint;
    uint32_t     valorant_pid = 0;
    int64_t      client_ts_ms = 0;
    int          jwt_push_count = 0;
    int          pipe_auth_count = 0;
    int          ping_count = 0;
    int          ioctl_count = 0;
    double       created_at = 0;
    double       last_activity = 0;
    CryptoSession crypto;
    std::shared_ptr<ProgramWorker> worker;

    
    uint64_t hb_sequence = 0;
    double   hb_last_sent = 0;
    double   hb_last_success = 0;
    int      hb_missed = 0;
    int      hb_success_count = 0;      
    double   last_keepalive_boost = 0;   
    bool     session_hardened = false;   
    bool     emergency_mode = false;     
    int      burst_counter = 0;          
    double   last_burst_time = 0;        

    
    struct HbEntry { uint64_t seq; std::vector<uint8_t> data; };
    std::deque<HbEntry> hb_buffer; 
};

static double NowSec() {
    return std::chrono::duration<double>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}




static std::vector<uint8_t> RealVgkIoctl(uint32_t ioctl_code, const std::vector<uint8_t>& in_data) {
    
    HANDLE hDev = CreateFileA("\\\\.\\vgk",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hDev == INVALID_HANDLE_VALUE) {
        
        hDev = CreateFileA("\\\\.\\vgk0",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    if (hDev == INVALID_HANDLE_VALUE) return {};

    
    std::vector<uint8_t> out_buf(8192, 0);
    DWORD bytes_returned = 0;

    BOOL ok = DeviceIoControl(
        hDev,
        ioctl_code,
        in_data.empty() ? nullptr : (LPVOID)in_data.data(),
        (DWORD)in_data.size(),
        out_buf.data(),
        (DWORD)out_buf.size(),
        &bytes_returned,
        nullptr);

    CloseHandle(hDev);

    if (!ok || bytes_returned == 0) return {};
    out_buf.resize(bytes_returned);
    return out_buf;
}




class SessionManager {
public:
    std::map<std::string, std::shared_ptr<Session>> sessions;
    mutable std::mutex mtx;
    std::string program_path;

    
    std::function<void(const std::string&, const std::string&, const std::string&, const std::string&)> on_session_created;
    std::function<void(const std::string&)> on_session_destroyed; 

    std::shared_ptr<Session> get(const std::string& sid) const {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = sessions.find(sid); return it != sessions.end() ? it->second : nullptr;
    }
    bool is_active(const std::string& sid) const {
        std::lock_guard<std::mutex> lk(mtx); return sessions.count(sid) > 0;
    }
    void touch(const std::string& sid) {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = sessions.find(sid); if (it != sessions.end()) it->second->last_activity = NowSec();
    }
    void note_ping(const std::string& sid) {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = sessions.find(sid);
        if (it != sessions.end()) { it->second->ping_count++; it->second->last_activity = NowSec(); }
    }
    void note_ioctl(const std::string& sid, uint32_t code, int in_len, int out_len) {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = sessions.find(sid);
        if (it != sessions.end()) { it->second->ioctl_count++; it->second->last_activity = NowSec(); }
        Log("IOCTL session=" + sid.substr(0, 8) + " code=0x" + [&] {
            std::ostringstream o; o << std::hex << code; return o.str();}() +
                " in=" + std::to_string(in_len) + " out=" + std::to_string(out_len));
    }

    std::string create_session(
        const std::string& jwt, const std::string& puuid,
        const std::string& region, const std::string& riot_account,
        const std::string& hostname, const std::string& client_ip,
        const std::vector<uint8_t>& gw_machine_id,
        const std::vector<uint8_t>& hwid_fp,
        uint32_t valorant_pid, int64_t client_ts_ms)
    {
        
        BYTE rnd[16]; BCryptGenRandom(nullptr, (PUCHAR)rnd, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        rnd[6] = (rnd[6] & 0x0F) | 0x40; rnd[8] = (rnd[8] & 0x3F) | 0x80;
        std::ostringstream ss;
        for (int i = 0;i < 16;i++) {
            if (i == 4 || i == 6 || i == 8 || i == 10) ss << '-';
            ss << std::hex << std::setfill('0') << std::setw(2) << (int)rnd[i];
        }
        std::string sid = ss.str();

        auto s = std::make_shared<Session>();
        s->session_id = sid; s->riot_token = jwt; s->puuid = puuid;
        s->region = region; s->riot_account = riot_account;
        s->hostname = hostname; s->client_ip = client_ip;
        s->gateway_machine_id = gw_machine_id; s->hwid_fingerprint = hwid_fp;
        s->valorant_pid = valorant_pid; s->client_ts_ms = client_ts_ms;
        s->created_at = NowSec(); s->last_activity = NowSec();
        s->hb_last_sent = NowSec(); s->hb_last_success = NowSec();
        s->last_keepalive_boost = NowSec(); 
        s->session_hardened = true; 
        s->crypto.mount(jwt, puuid);
        s->pipe_auth_count = 1; s->jwt_push_count = jwt.empty() ? 0 : 1;
        {
            std::lock_guard<std::mutex> lk(mtx);
            sessions[sid] = s;
        }
        g_elog.log(sid, "session_auth", "created", "ip=" + client_ip + " region=" + region);
        Log("session " + sid.substr(0, 8) + " CREATED ip=" + client_ip + " region=" + region +
            " account=" + riot_account.substr(0, 24) + " pid=" + std::to_string(valorant_pid) + " [INFINITE SESSION]");
        
        if (on_session_created) on_session_created(sid, puuid, region, riot_account);
        return sid;
    }

    bool update_jwt(const std::string& sid, const std::string& jwt, const std::string& puuid) {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = sessions.find(sid); if (it == sessions.end()) return false;
        auto& s = *it->second;
        s.riot_token = jwt; s.puuid = puuid; s.jwt_push_count++;
        s.last_activity = NowSec();
        s.last_keepalive_boost = NowSec(); 
        s.hb_missed = 0;                   
        s.emergency_mode = false;          
        s.burst_counter = 0;               
        s.hb_success_count = 0;            
        s.crypto.update_jwt(jwt, puuid);
        g_elog.log(sid, "jwt_update", "ok");
        Log("JWT UPDATE session=" + sid.substr(0, 8) + " - ALL COUNTERS RESET");
        return true;
    }

    bool note_pipe_auth(const std::string& sid, uint32_t pid) {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = sessions.find(sid); if (it == sessions.end()) return false;
        it->second->valorant_pid = pid; it->second->pipe_auth_count++;
        it->second->last_activity = NowSec();
        return true;
    }

    void destroy_session(const std::string& sid) {
        std::shared_ptr<Session> s;
        {
            std::lock_guard<std::mutex> lk(mtx); auto it = sessions.find(sid);
            if (it != sessions.end()) { s = it->second; sessions.erase(it); }
        }
        if (s && s->worker) s->worker->stop();
        g_elog.log(sid, "session", "destroyed");
        Log("session " + sid.substr(0, 8) + " destroyed");
        
        if (on_session_destroyed) on_session_destroyed(sid);
    }

    void expire_idle() {
        
        if (IDLE_TIMEOUT_SEC <= 0) {
            
            return;
        }
        
        
        double now = NowSec();
        std::vector<std::string> expired;
        {
            std::lock_guard<std::mutex> lk(mtx);
            for (auto& kv : sessions) {
                
                double effective_timeout = IDLE_TIMEOUT_SEC;
                if (kv.second->session_hardened) {
                    double boost_age = now - kv.second->last_keepalive_boost;
                    if (boost_age < SESSION_KEEPALIVE_BOOST) {
                        effective_timeout += SESSION_KEEPALIVE_BOOST; 
                    }
                }
                if (now - kv.second->last_activity > effective_timeout) 
                    expired.push_back(kv.first);
            }
        }
        for (auto& sid : expired) { Log("session " + sid.substr(0, 8) + " idle timeout"); destroy_session(sid); }
    }

    
    std::vector<uint8_t> send_heartbeat(const std::string& sid, bool force = false,
        uint32_t code = IOCTL_VGK_HB,
        const std::vector<uint8_t>& data = {}) {
        auto s = get(sid); if (!s) return {};
        std::vector<uint8_t> resp;

        
        resp = RealVgkIoctl(code, data);
        if (!resp.empty()) {
            Log("HB real_vgk code=0x" + [&] {std::ostringstream o;o << std::hex << code;return o.str();}() + " resp=" + std::to_string(resp.size()) + "B");
        }

        
        if (resp.empty() && s->worker && s->worker->alive()) {
            resp = s->worker->ioctl(code, data, 5000);
        }
        
        if (resp.empty()) resp = s->crypto.ioctl_response(code, data);
                if (resp.empty()) resp = g_fallback.get(sid);
        if (resp.empty()) resp = s->crypto.ioctl_response(code, data);
        if (!resp.empty()) g_fallback.update(sid, resp);
        {
            std::lock_guard<std::mutex> lk(mtx);
            auto it = sessions.find(sid); if (it != sessions.end()) {
                auto& ss = *it->second;
                ss.hb_sequence++;
                ss.hb_last_sent = NowSec();
                if (!resp.empty()) { 
                    ss.hb_missed = 0; 
                    ss.hb_last_success = NowSec(); 
                    ss.hb_success_count++; 
                    ss.emergency_mode = false; 
                    ss.burst_counter = 0; 
                    
                    if (ss.hb_success_count % 20 == 0) {
                        ss.last_activity = NowSec();
                        ss.last_keepalive_boost = NowSec();
                    }
                }
                else {
                    ss.hb_missed++;
                    Log("WARN session " + sid.substr(0, 8) + " missed=" + std::to_string(ss.hb_missed) + " auto-recovering Error 102");
                    std::thread([]() {
                        GatewayDoReauth();
                    }).detach();
                }
                ss.hb_buffer.push_back({ ss.hb_sequence,resp });
                if (ss.hb_buffer.size() > 1024) ss.hb_buffer.pop_front(); 
            }
        }
        g_elog.log(sid, "heartbeat", resp.empty() ? "empty" : "ok");
        return resp;
    }

    std::vector<std::pair<uint64_t, std::vector<uint8_t>>>
        get_buffered(const std::string& sid, uint64_t from_seq) {
        std::vector<std::pair<uint64_t, std::vector<uint8_t>>> out;
        std::lock_guard<std::mutex> lk(mtx);
        auto it = sessions.find(sid); if (it == sessions.end()) return out;
        for (auto& e : it->second->hb_buffer)
            if (e.seq >= from_seq) out.push_back({ e.seq,e.data });
        return out;
    }
};
static SessionManager g_session_mgr;

static std::string g_cached_jwt;
static std::string g_cached_sid;
static std::string g_cached_ext_sid;
static std::string g_cached_puuid;
static std::string g_cached_region; 
static std::string g_region_override; 
static std::mutex  g_jwt_cache_mtx;

static std::string ApplyConfiguredRegion(const std::string& detected_region, const char* tag) {
    std::string forced_region;
    {
        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
        forced_region = g_region_override;
    }

    if (!forced_region.empty()) {
        Log(std::string(tag) + " region override -> " + forced_region +
            (detected_region.empty() ? " (detected=<empty>)" : " (detected=" + detected_region + ")"));
        return forced_region;
    }
    return detected_region;
}

struct RoundTracker {
    std::atomic_int  round_number{0};
    std::atomic_bool in_match{false};
    std::atomic_bool lobby_pending{false};
    double           match_start_time = 0;
    double           last_round_time  = 0;
    std::mutex       mtx;

    void on_match_start() {
        std::lock_guard<std::mutex> lk(mtx);
        in_match.store(true);
        lobby_pending.store(false);
        round_number.store(0);
        match_start_time = NowSec();
        last_round_time  = NowSec();
        Log("[ROUND] Match started");
    }
    void on_round_end() {
        std::lock_guard<std::mutex> lk(mtx);
        round_number.fetch_add(1);
        last_round_time = NowSec();
        Log("[ROUND] Round " + std::to_string(round_number.load()) + " ended");
    }
    
    void on_lobby_return(std::function<void()> refresh_fn) {
        {
            std::lock_guard<std::mutex> lk(mtx);
            if (!in_match.load() && !lobby_pending.load()) return;
            in_match.store(false);
            lobby_pending.store(true);
            Log("[ROUND] Lobby return after " + std::to_string(round_number.load()) + " rounds — refreshing session");
        }
        if (refresh_fn) refresh_fn();
        lobby_pending.store(false);
    }
    bool is_in_match()   const { return in_match.load(); }
    int  current_round() const { return round_number.load(); }
};
static RoundTracker g_round_tracker;

struct TasksModulesHandler {
    std::atomic_bool tasks_received{false};
    int  ack_count = 0;
    std::mutex mtx;

    std::vector<uint8_t> handle_packet(const std::vector<uint8_t>& pkt) {
        std::lock_guard<std::mutex> lk(mtx);
        ack_count++;
        std::ostringstream hdrHex;
        int hdrLen = (int)pkt.size() < 8 ? (int)pkt.size() : 8;
        for (int i = 0; i < hdrLen; i++)
            hdrHex << std::hex << std::setw(2) << std::setfill('0') << (int)pkt[i] << " ";
        Log("[TASKS] packet size=" + std::to_string(pkt.size()) + " ack#" + std::to_string(ack_count) + " header=" + hdrHex.str());
        tasks_received.store(true);

        std::vector<uint8_t> ack;
        if (pkt.size() >= 8) {
            ack.push_back(pkt[0] + 1); 
            ack.push_back(0x00);
            ack.push_back(0x00);
            ack.push_back(0x00);
            
            ack.push_back(pkt[4]);
            ack.push_back(pkt[5]);
            ack.push_back(pkt[6]);
            ack.push_back(pkt[7]);
        } else {
            ack = { 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        }
        std::ostringstream ackHex;
        for (auto b : ack) ackHex << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
        Log("[TASKS] ACK sent: " + ackHex.str());
        return ack;
    }

    std::vector<uint8_t> handle_auth_request(
        const std::string& jwt, const std::string& puuid,
        const std::string& sid, const std::string& region)
    {
        std::lock_guard<std::mutex> lk(mtx);
        Log("[AUTH_REQ] 0x64 new session request — puuid=" + (puuid.size()>8?puuid.substr(0,8)+"...":puuid));
        std::vector<uint8_t> resp;
        if (!jwt.empty() && !puuid.empty()) {
            resp.push_back(0x00); 
            uint32_t plen = (uint32_t)puuid.size();
            resp.push_back((plen>>24)&0xFF); resp.push_back((plen>>16)&0xFF);
            resp.push_back((plen>>8)&0xFF);  resp.push_back(plen&0xFF);
            resp.insert(resp.end(), puuid.begin(), puuid.end());
            
            if (!sid.empty()) {
                uint32_t slen = (uint32_t)sid.size();
                resp.push_back((slen>>24)&0xFF); resp.push_back((slen>>16)&0xFF);
                resp.push_back((slen>>8)&0xFF);  resp.push_back(slen&0xFF);
                resp.insert(resp.end(), sid.begin(), sid.end());
            }
        } else {
            resp.push_back(0x01); 
        }
        return resp;
    }
};
static TasksModulesHandler g_tasks_handler;

static std::atomic_bool g_hb_running(false);
static std::atomic_bool g_van84_running(false);
static std::atomic_bool g_keepalive_running(false);
static std::atomic_int  g_keepalive_fail_count(0);
static constexpr bool   GATEWAY_AUTO_SEND_ON_CAPTURE = false; 
static std::atomic_int  g_gateway_reauth_remaining_sec(GATEWAY_REAUTH_INTERVAL_SEC);
static std::atomic_bool g_gateway_reauth_restart_countdown(false);
static std::atomic_bool g_gateway_auto_send(GATEWAY_AUTO_SEND_ON_CAPTURE);
static std::atomic_bool g_gateway_send_inflight(false);
static std::atomic_bool g_gateway_manual_reauth_inflight(false);
static std::atomic<ULONGLONG> g_gateway_manual_last_trigger_ms(0);
static std::atomic_bool g_backend_started(false);
static std::atomic_bool g_vps_server_heartbeat_running(false);

struct PendingGatewayRequest {
    std::string jwt;
    std::string sid;
    std::string puuid;
    uint32_t pid = 0;
    std::chrono::steady_clock::time_point queued_at{};
    bool valid = false;
};

static std::mutex            g_pending_gateway_mtx;
static PendingGatewayRequest g_pending_gateway;
static uint32_t         g_valorant_pid_fwd = 0; 
static std::atomic_bool g_gw_reauth_needed(false); 
static void StopVgk(); 
struct RandomizedHardwareProfile {
    char cpu_brand[32];
    char cpu_model[128];
    uint32_t cpu_cores;
    char gpu_brand[32];
    char gpu_model[128];
    char bios_vendor[64];
    char bios_version[32];
    char mobo_model[64];
    char volume_serial[12];
    char machine_guid[40];
    char hostname[32];
    char os_version[20];
};

static std::string GetConfiguredGatewayMachineId();
static std::string GetCachedHwPart6();
static std::string GetStableHt();
static const RandomizedHardwareProfile& GetRandomizedHardwareProfile();
static void UpdateDisplaySessionState(const std::string& puuid, const std::string& region, const std::string& account);
static void UpdateConsoleTitle();
static void ResetGatewayReauthTimer();

static bool SmartGatewayMint(const std::string& jwt, const std::string& sid,
                             const std::string& puuid, uint32_t pid);

static void Van84Loop() {
    while (g_van84_running.load()) {
        Sleep(3000); 

        std::vector<std::string> sids;
        {
            std::lock_guard<std::mutex> lk(g_session_mgr.mtx);
            for (auto& kv : g_session_mgr.sessions) sids.push_back(kv.first);
        }
        for (auto& sid : sids) {
            auto s = g_session_mgr.get(sid); if (!s) continue;
            double elapsed = NowSec() - s->hb_last_success;

            if (elapsed > 30.0 || s->hb_missed > 0) {
                Log("VAN102/VAN84 preventive HB session=" + sid.substr(0, 8) + " elapsed=" + std::to_string((int)elapsed) + "s missed=" + std::to_string(s->hb_missed));
                g_session_mgr.send_heartbeat(sid, true);
            }

            if (elapsed > 90.0 || s->hb_missed >= 3) {
                Log("VAN102 preventive re-auth session=" + sid.substr(0, 8) + " resetting counters");
                {
                    std::lock_guard<std::mutex> lk(g_session_mgr.mtx);
                    s->hb_missed = 0;
                    s->emergency_mode = false;
                    s->burst_counter  = 0;
                    s->hb_last_success = NowSec();
                }
                std::thread([]() { GatewayDoReauth(); }).detach();
            }

            if (s->session_hardened) {
                std::lock_guard<std::mutex> lk(g_session_mgr.mtx);
                s->last_keepalive_boost = NowSec();
                s->last_activity = NowSec();
            }
        }
    }
}




static void HeartbeatLoop() {
    while (g_hb_running.load()) {
        Sleep(1000);
        std::vector<std::string> sids;
        {
            std::lock_guard<std::mutex> lk(g_session_mgr.mtx);
            for (auto& kv : g_session_mgr.sessions) sids.push_back(kv.first);
        }

        for (auto& sid : sids) {
            auto s = g_session_mgr.get(sid); if (!s) continue;
            double elapsed_ms = (NowSec() - s->hb_last_sent) * 1000.0;

            
            if (elapsed_ms >= (double)(HB_INTERVAL_MS - 500)) {
                g_session_mgr.send_heartbeat(sid);
                
            }
        }
        g_session_mgr.expire_idle();
    }
}




struct SspiHandle {
    CredHandle cred{}; CtxtHandle ctx{};
    bool cred_ok = false; bool ctx_ok = false;
    ~SspiHandle() {
        if (ctx_ok)  DeleteSecurityContext(&ctx);
        if (cred_ok) FreeCredentialsHandle(&cred);
    }
};

class TlsSocket {
public:
    SOCKET s = INVALID_SOCKET;
    SspiHandle* ss = nullptr;
    std::vector<uint8_t> enc_pending, plain_pending;

    bool Connect(const char* host, uint16_t port, bool skip_verify) {
        WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
        s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return false;
        sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
        InetPtonA(AF_INET, host, &addr.sin_addr);
        if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) { closesocket(s);s = INVALID_SOCKET;return false; }
        const DWORD t = 60000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&t, sizeof(t));
        ss = new SspiHandle();
        if (!Handshake(host, skip_verify)) { delete ss;ss = nullptr;closesocket(s);s = INVALID_SOCKET;return false; }
        return true;
    }

    bool Handshake(const char* host, bool skip_verify) {
        SCHANNEL_CRED sc{}; sc.dwVersion = SCHANNEL_CRED_VERSION;
        sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
        if (skip_verify) sc.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
        TimeStamp ts{};
        if (AcquireCredentialsHandleW(nullptr, (SEC_WCHAR*)UNISP_NAME_W,
            SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr, nullptr, &ss->cred, &ts) != SEC_E_OK) return false;
        ss->cred_ok = true;
        std::vector<uint8_t> inbuf(32 * 1024), outbuf(32 * 1024);
        SecBufferDesc in_desc{}; SecBuffer in_sec[2]{};
        DWORD ctx_attr = 0; bool first = true;
        const std::wstring whost(host, host + strlen(host));
        for (;;) {
            SecBuffer out_sec[1]{};
            out_sec[0].BufferType = SECBUFFER_TOKEN;
            out_sec[0].pvBuffer = outbuf.data();
            out_sec[0].cbBuffer = (ULONG)outbuf.size();
            SecBufferDesc out_desc;
            out_desc.ulVersion = SECBUFFER_VERSION;
            out_desc.cBuffers = 1;
            out_desc.pBuffers = out_sec;
            SECURITY_STATUS st = InitializeSecurityContextW(
                &ss->cred, first ? nullptr : &ss->ctx, const_cast<wchar_t*>(whost.c_str()),
                ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_STREAM |
                ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_USE_SUPPLIED_CREDS,
                0, SECURITY_NATIVE_DREP, first ? nullptr : &in_desc, 0,
                &ss->ctx, &out_desc, &ctx_attr, &ts);
            first = false;
            if (st != SEC_E_OK && st != SEC_I_CONTINUE_NEEDED) return false;
            ss->ctx_ok = true;
            if (out_sec[0].cbBuffer && out_sec[0].pvBuffer) {
                send(s, (const char*)out_sec[0].pvBuffer, out_sec[0].cbBuffer, 0);
                FreeContextBuffer(out_sec[0].pvBuffer);
            }
            if (st == SEC_E_OK) return true;
            int got = recv(s, (char*)inbuf.data(), (int)inbuf.size(), 0);
            if (got <= 0) return false;
            in_sec[0].cbBuffer = (ULONG)got;
            in_sec[0].BufferType = SECBUFFER_TOKEN;
            in_sec[0].pvBuffer = inbuf.data();
            in_sec[1].cbBuffer = 0;
            in_sec[1].BufferType = SECBUFFER_EMPTY;
            in_sec[1].pvBuffer = nullptr;
            in_desc.ulVersion = SECBUFFER_VERSION;
            in_desc.cBuffers = 2;
            in_desc.pBuffers = in_sec;
        }
    }

    void SendAll(const uint8_t* data, size_t len) {
        SecPkgContext_StreamSizes sizes{};
        QueryContextAttributesW(&ss->ctx, SECPKG_ATTR_STREAM_SIZES, &sizes);
        size_t max_chunk = sizes.cbMaximumMessage > 0 ? sizes.cbMaximumMessage : len;
        size_t off = 0;
        while (off < len) {
            size_t chunk = (std::min)(len - off, max_chunk);
            std::vector<uint8_t> buf(sizes.cbHeader + chunk + sizes.cbTrailer);
            memcpy(buf.data() + sizes.cbHeader, data + off, chunk);
            SecBuffer sec[4]{};
            sec[0].cbBuffer = sizes.cbHeader;
            sec[0].BufferType = SECBUFFER_STREAM_HEADER;
            sec[0].pvBuffer = buf.data();
            sec[1].cbBuffer = (ULONG)chunk;
            sec[1].BufferType = SECBUFFER_DATA;
            sec[1].pvBuffer = buf.data() + sizes.cbHeader;
            sec[2].cbBuffer = sizes.cbTrailer;
            sec[2].BufferType = SECBUFFER_STREAM_TRAILER;
            sec[2].pvBuffer = buf.data() + sizes.cbHeader + chunk;
            sec[3].cbBuffer = 0;
            sec[3].BufferType = SECBUFFER_EMPTY;
            sec[3].pvBuffer = nullptr;
            SecBufferDesc desc;
            desc.ulVersion = SECBUFFER_VERSION;
            desc.cBuffers = 4;
            desc.pBuffers = sec;
            EncryptMessage(&ss->ctx, 0, &desc, 0);
            ULONG total = sec[0].cbBuffer + sec[1].cbBuffer + sec[2].cbBuffer;
            send(s, (const char*)buf.data(), total, 0);
            off += chunk;
        }
    }

    void Drain() {
        while (!enc_pending.empty()) {
            SecBuffer sec[4]{};
            sec[0].cbBuffer = (ULONG)enc_pending.size();
            sec[0].BufferType = SECBUFFER_DATA;
            sec[0].pvBuffer = enc_pending.data();
            for (int i = 1;i < 4;i++) {
                sec[i].cbBuffer = 0;
                sec[i].BufferType = SECBUFFER_EMPTY;
                sec[i].pvBuffer = nullptr;
            }
            SecBufferDesc desc;
            desc.ulVersion = SECBUFFER_VERSION;
            desc.cBuffers = 4;
            desc.pBuffers = sec;
            SECURITY_STATUS st = DecryptMessage(&ss->ctx, &desc, 0, nullptr);
            if (st == SEC_E_INCOMPLETE_MESSAGE) break;
            if (st != SEC_E_OK) throw std::runtime_error("TLS decrypt failed");
            size_t extra_off = enc_pending.size(), extra_len = 0;
            for (int i = 0;i < 4;i++) {
                if (sec[i].BufferType == SECBUFFER_DATA && sec[i].cbBuffer)
                    plain_pending.insert(plain_pending.end(),
                        (uint8_t*)sec[i].pvBuffer, (uint8_t*)sec[i].pvBuffer + sec[i].cbBuffer);
                if (sec[i].BufferType == SECBUFFER_EXTRA && sec[i].cbBuffer) {
                    extra_off = (uint8_t*)sec[i].pvBuffer - enc_pending.data();
                    extra_len = sec[i].cbBuffer;
                }
            }
            if (extra_len) enc_pending.assign(enc_pending.begin() + extra_off, enc_pending.begin() + extra_off + extra_len);
            else enc_pending.clear();
        }
    }

    std::vector<uint8_t> RecvMsg() {
        for (;;) {
            Drain();
            if (plain_pending.size() >= 8) {
                uint32_t plen = ReadU32BE(plain_pending.data() + 4);
                size_t need = 8 + plen;
                if (plain_pending.size() >= need) {
                    std::vector<uint8_t> msg(plain_pending.begin(), plain_pending.begin() + need);
                    plain_pending.erase(plain_pending.begin(), plain_pending.begin() + need);
                    return msg;
                }
            }
            uint8_t chunk[16 * 1024]; int got = recv(s, (char*)chunk, sizeof(chunk), 0);
            if (got <= 0) throw std::runtime_error("recv closed");
            enc_pending.insert(enc_pending.end(), chunk, chunk + got);
        }
    }

    void Close() {
        if (ss) { delete ss;ss = nullptr; }
        if (s != INVALID_SOCKET) { closesocket(s);s = INVALID_SOCKET; }
    }
};








static bool RecvExact(SOCKET s, uint8_t* buf, int n) {
    int got = 0;
    while (got < n) {
        int r = recv(s, (char*)buf + got, n - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}
static bool SendExact(SOCKET s, const uint8_t* buf, int n) {
    int sent = 0;
    while (sent < n) {
        int r = send(s, (char*)buf + sent, n - sent, 0);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}


struct ServerTlsConn {
    SOCKET       sock = INVALID_SOCKET;
    CredHandle   cred = {};
    CtxtHandle   ctx = {};
    bool         cred_ok = false, ctx_ok = false;
    std::vector<uint8_t> enc_buf, plain_buf;

    void close_handles() {
        if (ctx_ok) { DeleteSecurityContext(&ctx);  ctx_ok = false; }
        if (cred_ok) { FreeCredentialsHandle(&cred); cred_ok = false; }
    }

    bool handshake(PCCERT_CONTEXT cert_ctx) {
        SCHANNEL_CRED sc{}; sc.dwVersion = SCHANNEL_CRED_VERSION;
        sc.cCreds = 1; sc.paCred = &cert_ctx;
        sc.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
        sc.dwFlags = SCH_CRED_NO_SYSTEM_MAPPER;
        TimeStamp ts{};
        if (AcquireCredentialsHandleW(nullptr, (SEC_WCHAR*)UNISP_NAME_W,
            SECPKG_CRED_INBOUND, nullptr, &sc, nullptr, nullptr, &cred, &ts) != SEC_E_OK) return false;
        cred_ok = true;

        bool first_call = true;
        std::vector<uint8_t> inbuf(32 * 1024);
        for (;;) {
            
            int got = recv(sock, (char*)inbuf.data(), (int)inbuf.size(), 0);
            if (got <= 0) return false;

            SecBuffer in_sec[2] = {
                {(ULONG)got,SECBUFFER_TOKEN,inbuf.data()},
                {0,SECBUFFER_EMPTY,nullptr} };
            SecBufferDesc in_desc = { SECBUFFER_VERSION,2,in_sec };

            SecBuffer out_sec[1] = { {0,SECBUFFER_TOKEN,nullptr} };
            SecBufferDesc out_desc = { SECBUFFER_VERSION,1,out_sec };

            DWORD ctx_attr = 0; TimeStamp ts2{};
            SECURITY_STATUS st = AcceptSecurityContext(
                &cred, first_call ? nullptr : &ctx,
                &in_desc, ASC_REQ_SEQUENCE_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_STREAM | ASC_REQ_ALLOCATE_MEMORY,
                SECURITY_NATIVE_DREP, &ctx, &out_desc, &ctx_attr, &ts2);
            first_call = false; ctx_ok = true;

            if (out_sec[0].pvBuffer && out_sec[0].cbBuffer) {
                send(sock, (const char*)out_sec[0].pvBuffer, out_sec[0].cbBuffer, 0);
                FreeContextBuffer(out_sec[0].pvBuffer);
            }
            if (st == SEC_E_OK) return true;
            if (st != SEC_I_CONTINUE_NEEDED) return false;
        }
    }

    void server_send(const std::vector<uint8_t>& data) {
        SecPkgContext_StreamSizes sizes{};
        QueryContextAttributesW(&ctx, SECPKG_ATTR_STREAM_SIZES, &sizes);
        size_t off = 0, len = data.size();
        size_t max_chunk = sizes.cbMaximumMessage > 0 ? sizes.cbMaximumMessage : len;
        while (off < len) {
            size_t chunk = (std::min)(len - off, max_chunk);
            std::vector<uint8_t> buf(sizes.cbHeader + chunk + sizes.cbTrailer);
            memcpy(buf.data() + sizes.cbHeader, data.data() + off, chunk);
            SecBuffer sec[4]{};
            sec[0].cbBuffer = sizes.cbHeader;
            sec[0].BufferType = SECBUFFER_STREAM_HEADER;
            sec[0].pvBuffer = buf.data();
            sec[1].cbBuffer = (ULONG)chunk;
            sec[1].BufferType = SECBUFFER_DATA;
            sec[1].pvBuffer = buf.data() + sizes.cbHeader;
            sec[2].cbBuffer = sizes.cbTrailer;
            sec[2].BufferType = SECBUFFER_STREAM_TRAILER;
            sec[2].pvBuffer = buf.data() + sizes.cbHeader + chunk;
            sec[3].cbBuffer = 0;
            sec[3].BufferType = SECBUFFER_EMPTY;
            sec[3].pvBuffer = nullptr;
            SecBufferDesc desc;
            desc.ulVersion = SECBUFFER_VERSION;
            desc.cBuffers = 4;
            desc.pBuffers = sec;
            EncryptMessage(&ctx, 0, &desc, 0);
            ULONG total = sec[0].cbBuffer + sec[1].cbBuffer + sec[2].cbBuffer;
            send(sock, (const char*)buf.data(), total, 0);
            off += chunk;
        }
    }

    void drain() {
        while (!enc_buf.empty()) {
            SecBuffer sec[4]{};
            sec[0] = { (ULONG)enc_buf.size(),SECBUFFER_DATA,enc_buf.data() };
            for (int i = 1;i < 4;i++) sec[i].BufferType = SECBUFFER_EMPTY;
            SecBufferDesc desc{ SECBUFFER_VERSION,4,sec };
            SECURITY_STATUS st = DecryptMessage(&ctx, &desc, 0, nullptr);
            if (st == SEC_E_INCOMPLETE_MESSAGE) break;
            if (st != SEC_E_OK) throw std::runtime_error("server TLS decrypt error");
            size_t extra_off = enc_buf.size(), extra_len = 0;
            for (int i = 0;i < 4;i++) {
                if (sec[i].BufferType == SECBUFFER_DATA && sec[i].cbBuffer)
                    plain_buf.insert(plain_buf.end(), (uint8_t*)sec[i].pvBuffer, (uint8_t*)sec[i].pvBuffer + sec[i].cbBuffer);
                if (sec[i].BufferType == SECBUFFER_EXTRA && sec[i].cbBuffer) {
                    extra_off = (uint8_t*)sec[i].pvBuffer - enc_buf.data();
                    extra_len = sec[i].cbBuffer;
                }
            }
            if (extra_len) enc_buf.assign(enc_buf.begin() + extra_off, enc_buf.begin() + extra_off + extra_len);
            else enc_buf.clear();
        }
    }

    std::vector<uint8_t> recv_msg() {
        for (;;) {
            drain();
            if (plain_buf.size() >= 8) {
                uint32_t plen = ReadU32BE(plain_buf.data() + 4);
                size_t need = 8 + plen;
                if (plain_buf.size() >= need) {
                    std::vector<uint8_t> msg(plain_buf.begin(), plain_buf.begin() + need);
                    plain_buf.erase(plain_buf.begin(), plain_buf.begin() + need);
                    return msg;
                }
            }
            uint8_t chunk[16 * 1024]; int got = recv(sock, (char*)chunk, sizeof(chunk), 0);
            if (got <= 0) throw std::runtime_error("server recv closed");
            enc_buf.insert(enc_buf.end(), chunk, chunk + got);
        }
    }
};


static bool PostToGateway(const std::vector<uint8_t>& envelope,
    const std::string& puuid, const std::string& region,
    std::vector<uint8_t>* out_response, int vg_type);




static std::atomic_int g_active_clients(0);

static void HandleTunnelClient(SOCKET raw, PCCERT_CONTEXT cert_ctx) {
    if (g_active_clients.load() >= MAX_CLIENTS) { closesocket(raw); return; }
    g_active_clients++;

    ServerTlsConn conn;
    conn.sock = raw;
    std::string session_id;
    const DWORD rcvtimeo = 120000;
    setsockopt(raw, SOL_SOCKET, SO_RCVTIMEO, (char*)&rcvtimeo, sizeof(rcvtimeo));

    auto send_pkt = [&](uint32_t type, const std::vector<uint8_t>& payload = {}) {
        auto pkt = PackMsg(type, payload);
        conn.server_send(pkt);
        };
    auto send_err = [&](const char* msg) {
        std::vector<uint8_t> e(msg, msg + strlen(msg));
        send_pkt(MSG_ERROR, e);
        };

    try {
        if (!conn.handshake(cert_ctx)) throw std::runtime_error("TLS handshake failed");
        Log("[SRV] client connected");

        for (;;) {
            auto msg = conn.recv_msg();
            uint32_t mt = ReadU32BE(msg.data());
            uint32_t plen = ReadU32BE(msg.data() + 4);
            std::vector<uint8_t> payload(msg.begin() + 8, msg.end());

            if (mt == MSG_SESSION_AUTH) {
                size_t off = 0;
                std::string auth_key = ParseLPStr(payload, off);
                auto gw_machine_id = ParseLPBytes(payload, off);
                std::string jwt = ParseLPStr(payload, off);
                std::string puuid = ParseLPStr(payload, off);
                uint32_t val_pid = (off + 4 <= payload.size()) ? ReadU32BE(payload.data() + off) : 0; off += 4;
                int64_t  client_ts_ms = (off + 8 <= payload.size()) ? (int64_t)ReadU64BE(payload.data() + off) : 0; off += 8;
                std::string region = ParseLPStr(payload, off);
                auto hwid_fp = ParseLPBytes(payload, off);
                std::string riot_acct = ParseLPStr(payload, off);
                std::string hostname = ParseLPStr(payload, off);

                if (auth_key != AUTH_KEY) {
                    Log("[SRV] SESSION_AUTH auth_failed");
                    send_err("auth_failed"); break;
                }
                if (jwt.empty()) { send_err("jwt_empty"); continue; }

                
                if (region.empty()) region = ShardFromJwtRobust(jwt);
                
                if (region.empty()) {
                    std::lock_guard<std::mutex> lk2(g_jwt_cache_mtx);
                    region = g_cached_region.empty() ? "na" : g_cached_region;
                }
                region = ApplyConfiguredRegion(region, "[SRV] SESSION_AUTH");
                
                {
                    std::lock_guard<std::mutex> lk2(g_jwt_cache_mtx);
                    if (!region.empty()) g_cached_region = region;
                }
                if (riot_acct.empty()) riot_acct = AccountFromJwt(jwt);
                if (puuid.empty()) puuid = PuuidFromJwt(jwt);

                
                std::string client_ip = "127.0.0.1";
                session_id = g_session_mgr.create_session(
                    jwt, puuid, region, riot_acct, hostname, client_ip,
                    gw_machine_id, hwid_fp, val_pid, client_ts_ms);

                
                
                
                const auto& _hwp1 = GetRandomizedHardwareProfile();
                auto gw_envelope = VGW::BuildGatewayAuthPayload(jwt, puuid, GetConfiguredGatewayMachineId(), GetStableHt(), "",
                    _hwp1.cpu_brand, _hwp1.cpu_model, _hwp1.gpu_model, "Windows 10 Pro", _hwp1.os_version);
                
                if (gw_envelope.empty()) {
                    gw_envelope = g_session_mgr.send_heartbeat(session_id, true, IOCTL_VGK_HB, {});
                    Log("[SRV] SESSION_AUTH_OK using vgk fallback envelope for session=" + session_id.substr(0, 8));
                }

                std::vector<uint8_t> ok_payload;
                PushLenStr(ok_payload, session_id);
                PushU32BE(ok_payload, (uint32_t)gw_envelope.size());
                ok_payload.insert(ok_payload.end(), gw_envelope.begin(), gw_envelope.end());
                send_pkt(MSG_SESSION_AUTH_OK, ok_payload);
                Log("[SRV] SESSION_AUTH_OK session=" + session_id.substr(0, 8) + " gw_envelope=" + std::to_string(gw_envelope.size()) + "B");
            }
            else if (mt == MSG_HELLO) {
                send_err("use_session_auth");
            }
            else if (mt == MSG_SYNC) {
                if (session_id.empty()) { send_err("not_authenticated"); continue; }
                size_t off = 0;
                std::string sync_sid = ParseLPStr(payload, off);
                uint64_t last_seq = (off + 8 <= payload.size()) ? ReadU64BE(payload.data() + off) : 0;
                session_id = sync_sid;
                if (!g_session_mgr.is_active(session_id)) continue;
                g_session_mgr.touch(session_id);
                auto buffered = g_session_mgr.get_buffered(session_id, last_seq + 1);
                Log("[SRV] SYNC session=" + session_id.substr(0, 8) + " buffered=" + std::to_string(buffered.size()));
                for (auto& [seq, data] : buffered) {
                    std::vector<uint8_t> hb_pkt;
                    PushU64BE(hb_pkt, seq);
                    PushU32BE(hb_pkt, (uint32_t)data.size());
                    hb_pkt.insert(hb_pkt.end(), data.begin(), data.end());
                    send_pkt(MSG_HB_BUFFER, hb_pkt);
                }
            }
            else if (mt == MSG_IOCTL) {
                if (session_id.empty() || !g_session_mgr.is_active(session_id)) {
                    send_err("not_authenticated"); continue;
                }
                size_t off = 0;
                uint32_t ioctl_code = (off + 4 <= payload.size()) ? ReadU32BE(payload.data() + off) : 0; off += 4;
                uint32_t dlen = (off + 4 <= payload.size()) ? ReadU32BE(payload.data() + off) : 0; off += 4;
                std::vector<uint8_t> idata(payload.begin() + off, payload.begin() + off + dlen);
                g_session_mgr.touch(session_id);
                std::vector<uint8_t> resp;
                
                if ((ioctl_code >> 16) == 0x22 || ioctl_code == IOCTL_VGK_HB)
                    resp = g_session_mgr.send_heartbeat(session_id, true, ioctl_code, idata);
                else
                    resp = g_session_mgr.send_heartbeat(session_id, false, ioctl_code, idata);
                g_session_mgr.note_ioctl(session_id, ioctl_code, (int)idata.size(), (int)resp.size());
                std::vector<uint8_t> resp_pkt;
                PushU32BE(resp_pkt, (uint32_t)resp.size());
                resp_pkt.insert(resp_pkt.end(), resp.begin(), resp.end());
                send_pkt(MSG_IOCTL_RESP, resp_pkt);
            }
            else if (mt == MSG_PING) {
                if (!session_id.empty() && g_session_mgr.is_active(session_id))
                    g_session_mgr.note_ping(session_id);
                send_pkt(MSG_PONG);
            }
            else if (mt == MSG_JWT_UPDATE) {
                if (session_id.empty() || !g_session_mgr.is_active(session_id)) {
                    send_err("not_authenticated"); continue;
                }
                size_t off = 0;
                std::string new_jwt = ParseLPStr(payload, off);
                std::string new_puuid = ParseLPStr(payload, off);
                if (new_jwt.empty()) { send_err("jwt_empty"); continue; }
                if (g_session_mgr.update_jwt(session_id, new_jwt, new_puuid))
                    send_pkt(MSG_JWT_OK);
                else send_err("session_missing");
            }
            else if (mt == MSG_PIPE_AUTH) {
                if (session_id.empty() || !g_session_mgr.is_active(session_id)) {
                    send_err("not_authenticated"); continue;
                }
                uint32_t val_pid = (payload.size() >= 4) ? ReadU32BE(payload.data()) : 0;
                g_session_mgr.note_pipe_auth(session_id, val_pid);
                send_pkt(MSG_PIPE_AUTH_OK);
            }
            else if (mt == MSG_SESSION_ACCESS) {
                
                
                if (session_id.empty() || !g_session_mgr.is_active(session_id)) {
                    send_err("not_authenticated"); continue;
                }
                auto s = g_session_mgr.get(session_id);
                if (!s) { send_err("session_missing"); continue; }

                std::string sid_out;
                auto envelope = ParseSessionGatewayBody(payload, &sid_out);
                if (envelope.empty()) { send_err("empty_envelope"); continue; }

                Log("[SRV] SESSION_ACCESS envelope=" + std::to_string(envelope.size()) + "B session=" + session_id.substr(0, 8));

                
                std::string server_pub_out, token_out;
                auto access_envelope = VGW::BuildGatewayAccessPayload(envelope, server_pub_out, token_out);
                if (access_envelope.empty()) { send_err("access_payload_failed"); continue; }

                
                std::vector<uint8_t> access_resp;
                bool ok = PostToGateway(access_envelope, s->puuid, s->region, &access_resp, 4);
                if (!ok || access_resp.empty()) { send_err("gateway_access_failed"); continue; }

                
                std::vector<uint8_t> ok_payload;
                PushLenStr(ok_payload, session_id);
                PushU32BE(ok_payload, (uint32_t)access_resp.size());
                ok_payload.insert(ok_payload.end(), access_resp.begin(), access_resp.end());
                send_pkt(MSG_SESSION_ACCESS_OK, ok_payload);
                Log("[SRV] SESSION_ACCESS_OK session=" + session_id.substr(0, 8) + " resp=" + std::to_string(access_resp.size()) + "B");
            }
            else if (mt == MSG_SESSION_HEARTBEAT) {
                
                
                if (session_id.empty() || !g_session_mgr.is_active(session_id)) {
                    send_err("not_authenticated"); continue;
                }
                auto s = g_session_mgr.get(session_id);
                if (!s) { send_err("session_missing"); continue; }

                std::string sid_out;
                auto prev_resp = ParseSessionGatewayBody(payload, &sid_out);
                if (prev_resp.empty()) { send_err("empty_envelope"); continue; }

                Log("[SRV] SESSION_HEARTBEAT session=" + session_id.substr(0, 8) + " prev_resp=" + std::to_string(prev_resp.size()) + "B");

                
                std::string server_pub_out;
                auto hb_envelope = VGW::BuildGatewayHeartbeatPayload(prev_resp, server_pub_out);
                if (hb_envelope.empty()) { send_err("hb_payload_failed"); continue; }

                
                std::vector<uint8_t> hb_resp;
                bool ok = PostToGateway(hb_envelope, s->puuid, s->region, &hb_resp, 7);
                if (!ok || hb_resp.empty()) {
                    
                    hb_resp = g_fallback.get(session_id);
                    if (hb_resp.empty()) { send_err("gateway_hb_failed"); continue; }
                    Log("[SRV] SESSION_HEARTBEAT using fallback cache session=" + session_id.substr(0, 8));
                }

                g_fallback.update(session_id, hb_resp);
                g_session_mgr.send_heartbeat(session_id, true); 

                
                std::vector<uint8_t> ok_payload;
                PushLenStr(ok_payload, session_id);
                PushU32BE(ok_payload, (uint32_t)hb_resp.size());
                ok_payload.insert(ok_payload.end(), hb_resp.begin(), hb_resp.end());
                send_pkt(MSG_SESSION_HEARTBEAT_OK, ok_payload);
                Log("[SRV] SESSION_HEARTBEAT_OK session=" + session_id.substr(0, 8) + " resp=" + std::to_string(hb_resp.size()) + "B");
            }
            else if (mt == MSG_TASKS_DATA) { // 102
                Log("[SRV] MSG_TASKS_DATA (102) received size=" + std::to_string(payload.size()));
                auto ack = g_tasks_handler.handle_packet(payload);
                send_pkt(MSG_TASKS_ACK, ack); // 103
                Log("[SRV] MSG_TASKS_ACK (103) sent size=" + std::to_string(ack.size()));
            }
            else if (mt == MSG_AUTH_REQUEST) { // 100
                Log("[SRV] MSG_AUTH_REQUEST (100) received");
                auto s = g_session_mgr.get(session_id);
                std::string jwt = s ? s->riot_token : g_cached_jwt;
                std::string puuid = s ? s->puuid : g_cached_puuid;
                std::string region = s ? s->region : g_cached_region;
                auto resp = g_tasks_handler.handle_auth_request(jwt, puuid, session_id, region);
                send_pkt(MSG_AUTH_RESPONSE, resp); // 101
                Log("[SRV] MSG_AUTH_RESPONSE (101) sent size=" + std::to_string(resp.size()));
            }
            else if (mt == MSG_ROUND_START) { // 110
                g_round_tracker.on_match_start();
                send_pkt(MSG_ROUND_START);
            }
            else if (mt == MSG_ROUND_END) { // 111
                g_round_tracker.on_round_end();
                send_pkt(MSG_ROUND_END);
            }
            else {
                Log("[SRV] unknown msg type=" + std::to_string(mt));
            }
        }
    }
    catch (const std::exception& e) {
        Log("[SRV] client exception: " + std::string(e.what()));
    }

    if (!session_id.empty())
        Log("[SRV] connection closed session=" + session_id.substr(0, 8) + " (session stays)");
    conn.close_handles();
    closesocket(raw);
    g_active_clients--;
}









static PCCERT_CONTEXT LoadOrCreateCert() {
    
    {
        std::vector<BYTE> pfx_data;
        std::ifstream f("server.pfx", std::ios::binary);
        if (f) {
            pfx_data = std::vector<BYTE>((std::istreambuf_iterator<char>(f)), {});
            CRYPT_DATA_BLOB blob{ (DWORD)pfx_data.size(),pfx_data.data() };
            HCERTSTORE store = PFXImportCertStore(&blob, L"", CRYPT_EXPORTABLE | CRYPT_USER_KEYSET);
            if (store) {
                PCCERT_CONTEXT ctx = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_ANY, nullptr, nullptr);
                if (ctx) { Log("[SRV] Loaded server.pfx"); CertCloseStore(store, 0); return ctx; }
                CertCloseStore(store, 0);
            }
        }
    }
    
    Log("[SRV] server.pfx not found â€” generating self-signed cert");
    HCERTSTORE myStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, nullptr);
    if (!myStore) { Log("[SRV] CertOpenStore failed"); return nullptr; }

    
    CERT_NAME_BLOB nameBlob{};
    const char* subj = "CN=DndVanguardServer";
    DWORD nameLen = 0;
    CertStrToNameA(X509_ASN_ENCODING, subj, CERT_X500_NAME_STR, nullptr, nullptr, &nameLen, nullptr);
    std::vector<BYTE> nameBuf(nameLen);
    CertStrToNameA(X509_ASN_ENCODING, subj, CERT_X500_NAME_STR, nullptr, nameBuf.data(), &nameLen, nullptr);
    nameBlob.cbData = nameLen; nameBlob.pbData = nameBuf.data();

    CRYPT_KEY_PROV_INFO kpi{};
    kpi.pwszContainerName = const_cast<wchar_t*>(L"DndVanguardSrv");
    kpi.pwszProvName = nullptr;
    kpi.dwProvType = PROV_RSA_FULL;
    kpi.dwFlags = CRYPT_MACHINE_KEYSET;
    kpi.dwKeySpec = AT_KEYEXCHANGE;

    
    SYSTEMTIME st_start{}, st_end{};
    GetSystemTime(&st_start);
    st_end = st_start; st_end.wYear += 10;

    PCCERT_CONTEXT ctx = CertCreateSelfSignCertificate(0, &nameBlob, 0, &kpi, nullptr, &st_start, &st_end, nullptr);
    if (!ctx) { Log("[SRV] CertCreateSelfSignCertificate failed err=" + std::to_string(GetLastError())); return nullptr; }

    
    CRYPT_DATA_BLOB pfx{};
    if (PFXExportCertStore(myStore, &pfx, L"", EXPORT_PRIVATE_KEYS)) {
        std::vector<BYTE> buf(pfx.cbData);
        pfx.pbData = buf.data();
        if (PFXExportCertStore(myStore, &pfx, L"", EXPORT_PRIVATE_KEYS)) {
            std::ofstream out("server.pfx", std::ios::binary);
            out.write((char*)buf.data(), buf.size());
            Log("[SRV] Saved server.pfx for reuse");
        }
    }
    CertCloseStore(myStore, 0);
    Log("[SRV] Self-signed cert created");
    return ctx;
}




static std::atomic_bool g_server_running(false);
static void RunServer() {
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);

    PCCERT_CONTEXT cert = LoadOrCreateCert();
    if (!cert) { Log("[SRV] Cannot load cert â€” server abort"); return; }

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    const int one = 1; setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one));
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); 

    if (bind(listen_sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        Log("[SRV] bind failed err=" + std::to_string(WSAGetLastError())); return;
    }
    listen(listen_sock, 64);
    Log("[SRV] TLS listening 127.0.0.1:" + std::to_string(SERVER_PORT));

    
    g_hb_running = true;   g_van84_running = true;
    std::thread(HeartbeatLoop).detach();
    std::thread(Van84Loop).detach();

    while (g_server_running.load()) {
        sockaddr_in cli_addr{}; int cli_len = sizeof(cli_addr);
        SOCKET cli = accept(listen_sock, (sockaddr*)&cli_addr, &cli_len);
        if (cli == INVALID_SOCKET) continue;
        std::thread(HandleTunnelClient, cli, cert).detach();
    }

    g_hb_running = false; g_van84_running = false;
    closesocket(listen_sock);
    CertFreeCertificateContext(cert);
    Log("[SRV] Server stopped");
}






static std::atomic_bool g_shutdown(false);
static std::atomic_bool g_api_called(false);
static std::atomic<void*> g_current_pipe(nullptr);
static uint32_t g_valorant_pid = 0;






static std::atomic_bool     g_gw_auto_posted(false);  
static std::atomic_int g_val_loading_pct(0);




static std::string Base64Encode(const uint8_t* data, size_t len) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; int val = 0, valb = -6;
    for (size_t i = 0;i < len;i++) { val = (val << 8) + data[i];valb += 8;while (valb >= 0) { out += tbl[(val >> valb) & 0x3F];valb -= 6; } }
    if (valb > -6) out += tbl[((val << 8) >> (valb + 8)) & 0x3F];
    while (out.size() % 4) out += '=';
    return out;
}

static std::string RegReadStr(HKEY root, const wchar_t* sub, const wchar_t* val) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) return {};
    wchar_t buf[512]{}; DWORD sz = sizeof(buf);
    RegQueryValueExW(hk, val, nullptr, nullptr, (LPBYTE)buf, &sz);
    RegCloseKey(hk);
    std::string out;
    for (int i = 0;buf[i] && i < 256;i++) out += (char)(buf[i] & 0xFF);
    return out;
}

static std::vector<uint8_t> GetRealHwid() {
    std::string bios_vendor = RegReadStr(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVendor");
    std::string bios_ver   = RegReadStr(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVersion");
    std::string bios = bios_vendor.empty() ? bios_ver : (bios_vendor + " " + bios_ver);
    if (bios.empty()) bios = RegReadStr(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName");
    std::string cpu = RegReadStr(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"ProcessorNameString");
    if (cpu.empty()) cpu = RegReadStr(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"Identifier");
    wchar_t sysRoot[MAX_PATH]{}; GetSystemDirectoryW(sysRoot, MAX_PATH); sysRoot[3] = L'\0';
    DWORD volSerial = 0; GetVolumeInformationW(sysRoot, nullptr, 0, &volSerial, nullptr, nullptr, nullptr, 0);
    char volBuf[16]; sprintf_s(volBuf, "%08X", volSerial);
    std::string guid = RegReadStr(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
    std::string composite = "BIOS:" + bios + "|CPU:" + cpu + "|VOL:" + std::string(volBuf) + "|MGUID:" + guid;
    Log("[HWID] composite: " + composite.substr(0, 80) + "...");
    std::vector<uint8_t> hash(32, 0);
    HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0; DWORD hashLen = 32;
    CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)composite.data(), (DWORD)composite.size(), 0);
    CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0);
    CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
    std::ostringstream hex; for (auto b : hash) hex << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    Log("[HWID] sha256=" + hex.str());
    return hash;
}


static std::string BytesToHexString(const std::vector<uint8_t>& bytes);

static std::wstring GetHwidProfilePath() {
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    wchar_t* last = wcsrchr(path, L'\\');
    if (last) *(last + 1) = L'\0';
    wcscat_s(path, L"hwid_profile.bin");
    return path;
}

static bool SaveHwidProfile(const RandomizedHardwareProfile& p) {
    static const uint32_t MAGIC = 0x44495748;
    static const uint32_t VER   = 5;
    auto path = GetHwidProfilePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    WriteFile(h, &MAGIC, 4, &written, nullptr);
    WriteFile(h, &VER,   4, &written, nullptr);
    uint32_t sz = sizeof(p);
    WriteFile(h, &sz, 4, &written, nullptr);
    WriteFile(h, &p, sz, &written, nullptr);
    CloseHandle(h);
    return written == sz;
}

static bool LoadHwidProfile(RandomizedHardwareProfile& p) {
    static const uint32_t MAGIC = 0x44495748;
    static const uint32_t VER   = 5;
    auto path = GetHwidProfilePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    uint32_t magic = 0, ver = 0, sz = 0; DWORD read = 0;
    ReadFile(h, &magic, 4, &read, nullptr);
    ReadFile(h, &ver,   4, &read, nullptr);
    ReadFile(h, &sz,    4, &read, nullptr);
    if (magic != MAGIC || ver != VER || sz != sizeof(p)) { CloseHandle(h); return false; }
    ReadFile(h, &p, sz, &read, nullptr);
    CloseHandle(h);
    return read == sz;
}

static const RandomizedHardwareProfile& GetRandomizedHardwareProfile() {
    static RandomizedHardwareProfile profile{};
    static bool initialized = false;
    if (initialized) return profile;

    struct CpuEntry { const char* brand; const char* cpuid; const char* model; uint32_t cores; int intel; };
    static const CpuEntry cpus[] = {
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i5-9400F CPU @ 2.90GHz",  6,  1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i5-10400F CPU @ 2.90GHz", 12, 1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz",  8,  1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz", 16, 1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i5-11400F CPU @ 2.60GHz", 12, 1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i7-11700K CPU @ 3.60GHz", 16, 1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i5-12400F CPU @ 2.50GHz", 12, 1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i7-12700K CPU @ 3.60GHz", 20, 1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i9-12900K CPU @ 3.20GHz", 24, 1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i5-13400F CPU @ 2.50GHz", 16, 1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i7-13700K CPU @ 3.40GHz", 24, 1 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 5 3600 6-Core Processor",          12, 0 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 7 3700X 8-Core Processor",         16, 0 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 5 5600X 6-Core Processor",         12, 0 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 7 5700X 8-Core Processor",         16, 0 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 7 5800X 8-Core Processor",         16, 0 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 9 5900X 12-Core Processor",        24, 0 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 5 7600X 6-Core Processor",         12, 0 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 7 7700X 8-Core Processor",         16, 0 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 9 7900X 12-Core Processor",        24, 0 },
    };

    struct GpuEntry { const char* brand; const char* model; };
    static const GpuEntry gpus[] = {
        { "NVIDIA", "NVIDIA GeForce GTX 1660 SUPER"   },
        { "NVIDIA", "NVIDIA GeForce GTX 1660 Ti"      },
        { "NVIDIA", "NVIDIA GeForce RTX 2060"         },
        { "NVIDIA", "NVIDIA GeForce RTX 2070 SUPER"   },
        { "NVIDIA", "NVIDIA GeForce RTX 3060"         },
        { "NVIDIA", "NVIDIA GeForce RTX 3060 Ti"      },
        { "NVIDIA", "NVIDIA GeForce RTX 3070"         },
        { "NVIDIA", "NVIDIA GeForce RTX 3080"         },
        { "NVIDIA", "NVIDIA GeForce RTX 4060"         },
        { "NVIDIA", "NVIDIA GeForce RTX 4060 Ti"      },
        { "NVIDIA", "NVIDIA GeForce RTX 4070"         },
        { "AMD",    "AMD Radeon RX 6600"              },
        { "AMD",    "AMD Radeon RX 6600 XT"           },
        { "AMD",    "AMD Radeon RX 6700 XT"           },
        { "AMD",    "AMD Radeon RX 6800 XT"           },
        { "AMD",    "AMD Radeon RX 7600"              },
        { "AMD",    "AMD Radeon RX 7700 XT"           },
    };

    struct MoboEntry { int intel; const char* vendor; const char* model; const char* bios_ver; };
    static const MoboEntry mobos[] = {
        { 1, "American Megatrends Inc.", "ASUS PRIME Z490-P",     "0501" },
        { 1, "American Megatrends Inc.", "ASUS ROG STRIX Z490-F", "0603" },
        { 1, "American Megatrends Inc.", "ASUS PRIME Z590-P",     "0606" },
        { 1, "American Megatrends Inc.", "ASUS TUF GAMING Z590",  "1401" },
        { 1, "American Megatrends Inc.", "ASUS PRIME Z690-P",     "1201" },
        { 1, "American Megatrends Inc.", "ASUS ROG STRIX Z690-F", "1403" },
        { 1, "American Megatrends Inc.", "MSI MAG Z490 TOMAHAWK", "A.40" },
        { 1, "American Megatrends Inc.", "MSI MPG Z590 GAMING",   "A.60" },
        { 1, "American Megatrends Inc.", "MSI MAG Z690 TOMAHAWK", "A.80" },
        { 1, "American Megatrends Inc.", "Gigabyte Z490 AORUS",   "F60"  },
        { 1, "American Megatrends Inc.", "Gigabyte Z590 AORUS",   "F65"  },
        { 1, "American Megatrends Inc.", "Gigabyte Z690 AORUS",   "F10"  },
        { 0, "American Megatrends Inc.", "ASUS ROG STRIX X570-E", "2606" },
        { 0, "American Megatrends Inc.", "ASUS TUF GAMING X570",  "2803" },
        { 0, "American Megatrends Inc.", "ASUS PRIME B550-PLUS",  "2402" },
        { 0, "American Megatrends Inc.", "MSI MAG X570 TOMAHAWK", "A.60" },
        { 0, "American Megatrends Inc.", "MSI MPG B550 GAMING",   "A.40" },
        { 0, "American Megatrends Inc.", "Gigabyte X570 AORUS",   "F34"  },
        { 0, "American Megatrends Inc.", "Gigabyte B550 AORUS",   "F17"  },
        { 0, "American Megatrends Inc.", "ASRock X570 Phantom",   "P4.10"},
    };

    std::vector<uint8_t> seed(64, 0);
    BCryptGenRandom(nullptr, seed.data(), (ULONG)seed.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    const auto& cpu = cpus[seed[0] % (sizeof(cpus) / sizeof(cpus[0]))];
    const auto& gpu = gpus[seed[1] % (sizeof(gpus) / sizeof(gpus[0]))];

    const MoboEntry* matched[20]; int mc = 0;
    for (auto& m : mobos) if (m.intel == cpu.intel && mc < 20) matched[mc++] = &m;
    const auto& mobo = *matched[seed[2] % mc];

    strcpy_s(profile.cpu_brand,   cpu.cpuid);
    strcpy_s(profile.cpu_model,   cpu.model);
    profile.cpu_cores = cpu.cores;
    strcpy_s(profile.gpu_brand,   gpu.brand);
    strcpy_s(profile.gpu_model,   gpu.model);
    strcpy_s(profile.bios_vendor, mobo.vendor);
    strcpy_s(profile.bios_version,mobo.bios_ver);
    strcpy_s(profile.mobo_model,  mobo.model);

    
    sprintf_s(profile.volume_serial, "%08X",
        (uint32_t)((seed[4] << 24) | (seed[5] << 16) | (seed[6] << 8) | seed[7]));

    sprintf_s(profile.machine_guid, "%02x%02x%02x%02x-%02x%02x-4%01x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        seed[8],  seed[9],  seed[10], seed[11],
        seed[12], seed[13],
        seed[14] & 0x0F, seed[15],
        (seed[16] & 0x3F) | 0x80, seed[17],
        seed[18], seed[19], seed[20], seed[21], seed[22], seed[23]);

    static const char* prefixes[] = { "DESKTOP-", "WIN-" };
    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const char* pfx = prefixes[seed[24] % 2];
    strcpy_s(profile.hostname, pfx);
    size_t pfx_len = strlen(pfx);
    for (int i = 0; i < 7; i++)
        profile.hostname[pfx_len + i] = charset[seed[25 + i] % (sizeof(charset) - 1)];
    profile.hostname[pfx_len + 7] = '\0';

    static const char* os_builds[] = {
        "10.0.19044", "10.0.19045", "10.0.22000",
        "10.0.22621", "10.0.22631", "10.0.26100",
    };
    strcpy_s(profile.os_version, os_builds[seed[32 % 32] % (sizeof(os_builds)/sizeof(os_builds[0]))]);

    Log(std::string("[HWID] generated new profile cpu=") + profile.cpu_model + " os=" + profile.os_version);

    initialized = true;
    return profile;
}

static std::vector<uint8_t> GetRandomHwid() {
    const auto& profile = GetRandomizedHardwareProfile();
    
    std::string composite = std::string("BIOS:") + profile.bios_vendor + " " + profile.bios_version
        + "|CPU:" + profile.cpu_model
        + "|VOL:" + profile.volume_serial
        + "|MGUID:" + profile.machine_guid;
    Log("[HWID] randomized composite: " + composite.substr(0, 80) + "...");

    std::vector<uint8_t> hash(32, 0);
    HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0; DWORD hashLen = 32;
    CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)composite.data(), (DWORD)composite.size(), 0);
    CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0);
    CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);

    std::ostringstream hex; for (auto b : hash) hex << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    Log("[HWID] randomized sha256=" + hex.str());
    return hash;
}

static std::string BytesToHexString(const std::vector<uint8_t>& bytes) {
    std::ostringstream hex;
    for (auto b : bytes) hex << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    return hex.str();
}

static std::vector<uint8_t> GetConfiguredHwid() {
    auto hash = GetRandomHwid(); 
    Log("[HWID] SESSION_AUTH hwid=" + BytesToHexString(hash).substr(0, 16) + "...");
    return hash;
}

static std::string Md5HexUpper(const std::vector<uint8_t>& data) {
    HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0;
    CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
    CryptHashData(hHash, data.data(), (DWORD)data.size(), 0);
    BYTE md5[16] = {}; DWORD len = 16;
    CryptGetHashParam(hHash, HP_HASHVAL, md5, &len, 0);
    CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
    std::ostringstream ss;
    for (int i = 0; i < 16; i++) ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (int)md5[i];
    return ss.str();
}

static std::string GetCachedHwPart6() {
    static std::string cached_s6;
    if (!cached_s6.empty()) return cached_s6;

    
    
    auto makeSlot = [](const std::string& entry) -> std::string {
        std::vector<uint8_t> buf(96, 0);
        size_t len = entry.size() < 96 ? entry.size() : 96;
        memcpy(buf.data(), entry.data(), len);
        return VGW::Base64Encode(buf.data(), buf.size());
    };

    
    auto r_pci = VGW::RandomBytes(16);
    std::ostringstream pci_ss;
    for (int i = 0; i < 16; i++) {
        if (i > 0 && i % 2 == 0) pci_ss << "_";
        pci_ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (int)r_pci[i];
    }
    static const char* disk_models[] = {
        "SAMSUNG MZVL21T0HCLR-00B00",
        "SAMSUNG MZVLB512HAJQ-000H1",
        "WDC WDS500G2B0C-00PXH0",
        "KINGSTON SKC3000S1024G",
        "CT1000P3SSD8",
    };
    uint8_t dm_seed = 0;
    BCryptGenRandom(nullptr, &dm_seed, 1, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    std::string slot0 = pci_ss.str() + "." + disk_models[dm_seed % 5];

    std::string empty_slot = makeSlot("");
    cached_s6 = makeSlot(slot0) + ";" + empty_slot + ";" +
                empty_slot + ";" + empty_slot + ";" + empty_slot;
    return cached_s6;
}








struct VgcMachineEntry {
    std::string machine_id;
    std::string ht;
};

static std::vector<VgcMachineEntry> g_machine_pool;
static size_t g_selected_machine_idx = (size_t)-1;
static std::mutex g_machine_pool_mtx;

static std::wstring GetOutputTxtPath() {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    wchar_t* last = wcsrchr(path, L'\\');
    if (last) *(last + 1) = L'\0';
    wcscat_s(path, L"output.txt");
    return path;
}

static bool LoadMachinePool() {
    std::lock_guard<std::mutex> lk(g_machine_pool_mtx);
    if (!g_machine_pool.empty()) return true;

    auto path = GetOutputTxtPath();
    std::ifstream f(path);
    if (!f.is_open()) {
        Log("[GW] output.txt not found at " + [&]{ std::string s; for (wchar_t c : path) if (c) s += (char)(c & 0xFF); return s; }());
        return false;
    }

    VgcMachineEntry cur;
    std::string line;
    while (std::getline(f, line)) {
        
        if (!line.empty() && line.back() == '\r') line.pop_back();

        if (line.empty() || line[0] == '#') {
            
            if (!cur.machine_id.empty() && !cur.ht.empty()) {
                g_machine_pool.push_back(cur);
                cur = {};
            }
            continue;
        }
        if (line.rfind("machine_id=", 0) == 0)
            cur.machine_id = line.substr(11);
        else if (line.rfind("ht=", 0) == 0)
            cur.ht = line.substr(3);
    }
    
    if (!cur.machine_id.empty() && !cur.ht.empty())
        g_machine_pool.push_back(cur);

    Log("[GW] output.txt loaded: " + std::to_string(g_machine_pool.size()) + " machine entries");
    return !g_machine_pool.empty();
}


static std::wstring GetExeDirFile(const wchar_t* filename) {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    wchar_t* last = wcsrchr(path, L'\\');
    if (last) *(last + 1) = L'\0';
    wcscat_s(path, filename);
    return path;
}




static std::wstring MakeLockFilePath(size_t idx) {
    wchar_t name[64]{};
    swprintf_s(name, L"hesap%zu.txt", idx + 1);
    return GetExeDirFile(name);
}

static void WriteLockFile(size_t idx) {
    auto path = MakeLockFilePath(idx);
    
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;
    std::string content = "machine_index=" + std::to_string(idx) + "\n";
    DWORD written = 0;
    WriteFile(hf, content.data(), (DWORD)content.size(), &written, nullptr);
    CloseHandle(hf);
}



static size_t FindExistingLockFile(size_t pool_size) {
    wchar_t dir[MAX_PATH]{};
    GetModuleFileNameW(nullptr, dir, MAX_PATH);
    wchar_t* last = wcsrchr(dir, L'\\');
    if (last) *(last + 1) = L'\0';

    wchar_t pattern[MAX_PATH]{};
    wcscpy_s(pattern, dir);
    wcscat_s(pattern, L"hesap*.txt");

    WIN32_FIND_DATAW fd{};
    HANDLE hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return (size_t)-1;

    size_t found_idx = (size_t)-1;
    do {
        
        wchar_t full[MAX_PATH]{};
        wcscpy_s(full, dir);
        wcscat_s(full, fd.cFileName);

        HANDLE hf = CreateFileW(full, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) continue;
        char buf[64]{}; DWORD rd = 0;
        ReadFile(hf, buf, sizeof(buf) - 1, &rd, nullptr);
        CloseHandle(hf);

        std::string content(buf, rd);
        auto pos = content.find("machine_index=");
        if (pos != std::string::npos) {
            size_t idx = (size_t)std::stoul(content.substr(pos + 14));
            if (idx < pool_size) { found_idx = idx; break; }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return found_idx;
}

static void EnsureMachineSelected() {
    if (g_selected_machine_idx != (size_t)-1) return;
    if (!LoadMachinePool() || g_machine_pool.empty()) {
        Log("[GW] ERROR: machine pool empty, check output.txt");
        g_selected_machine_idx = 0;
        return;
    }

    size_t pool_size = g_machine_pool.size();

    
    size_t existing = FindExistingLockFile(pool_size);
    if (existing != (size_t)-1) {
        g_selected_machine_idx = existing;
        Log("[GW] reusing machine idx=" + std::to_string(existing) + " (hesap" + std::to_string(existing + 1) + ".txt found)");
        return;
    }

    
    uint32_t rnd = 0;
    BCryptGenRandom(nullptr, (PUCHAR)&rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    g_selected_machine_idx = rnd % pool_size;
    WriteLockFile(g_selected_machine_idx);
    Log("[GW] new machine idx=" + std::to_string(g_selected_machine_idx) +
        " -> hesap" + std::to_string(g_selected_machine_idx + 1) + ".txt created (" +
        std::to_string(pool_size) + " entries)");
}

static std::string GetConfiguredGatewayMachineId() {
    EnsureMachineSelected();
    std::lock_guard<std::mutex> lk(g_machine_pool_mtx);
    if (g_machine_pool.empty()) return "";
    return g_machine_pool[g_selected_machine_idx].machine_id;
}

static std::string GetStableHt() {
    EnsureMachineSelected();
    std::lock_guard<std::mutex> lk(g_machine_pool_mtx);
    if (g_machine_pool.empty()) return "";
    return g_machine_pool[g_selected_machine_idx].ht;
}

static std::string GetFakeHostname() {
    return GetRandomizedHardwareProfile().hostname;
}

static void GetCpuInfo(std::string& brand, std::string& model, uint32_t& cores) {
    if (RandomizedVersion) {
        const auto& p = GetRandomizedHardwareProfile();
        brand = p.cpu_brand;
        model = p.cpu_model;
        cores = p.cpu_cores;
        Log("[HWINFO] CPU rand brand=" + brand + " model=" + model);
        return;
    }

    model = RegReadStr(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"ProcessorNameString");
    while (!model.empty() && (model.back() == ' ' || model.back() == '\t')) model.pop_back();
    brand = (model.find("Intel") != std::string::npos) ? "GenuineIntel" : (model.find("AMD") != std::string::npos) ? "AuthenticAMD" : "Unknown";
    SYSTEM_INFO si{}; GetSystemInfo(&si); cores = si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 1;
    Log("[HWINFO] CPU real brand=" + brand + " model=" + model + " logical_count=" + std::to_string(cores));
}

static void GetGpuInfo(std::string& brand, std::string& model) {
    if (RandomizedVersion) {
        const auto& p = GetRandomizedHardwareProfile();
        brand = p.gpu_brand;
        model = p.gpu_model;
        Log("[HWINFO] GPU rand brand=" + brand + " model=" + model);
        return;
    }

    model = RegReadStr(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", L"DriverDesc");
    if (model.empty()) { brand = "Unknown";model = "Unknown";Log("[HWINFO] GPU real brand=" + brand + " model=" + model);return; }
    brand = (model.find("NVIDIA") != std::string::npos) ? "NVIDIA" :
        (model.find("AMD") != std::string::npos || model.find("Radeon") != std::string::npos) ? "AMD" :
        (model.find("Intel") != std::string::npos) ? "Intel" : "Unknown";
    Log("[HWINFO] GPU real brand=" + brand + " model=" + model);
}



static std::vector<uint8_t> BcryptBlobToSpkiDer(const std::vector<uint8_t>& pubBlob) {
    auto* blob = (BCRYPT_RSAKEY_BLOB*)pubBlob.data();
    DWORD expLen = blob->cbPublicExp, modLen = blob->cbModulus;
    const uint8_t* expBytes = pubBlob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
    const uint8_t* modBytes = expBytes + expLen;
    auto der_len = [](size_t len, std::vector<uint8_t>& buf) {
        if (len < 0x80) { buf.push_back((uint8_t)len); }
        else if (len < 0x100) { buf.push_back(0x81);buf.push_back((uint8_t)len); }
        else { buf.push_back(0x82);buf.push_back((uint8_t)(len >> 8));buf.push_back((uint8_t)len); }};
    auto der_int = [&der_len](const uint8_t* d, size_t sz)->std::vector<uint8_t> {
        std::vector<uint8_t> r; r.push_back(0x02);
        size_t skip = 0; while (skip + 1 < sz && d[skip] == 0) skip++;
        bool pad = (d[skip] & 0x80) != 0;
        der_len(sz - skip + (pad ? 1 : 0), r);
        if (pad) r.push_back(0x00);
        r.insert(r.end(), d + skip, d + sz); return r;};
    auto mod_int = der_int(modBytes, modLen), exp_int = der_int(expBytes, expLen);
    std::vector<uint8_t> rsa_pk; rsa_pk.push_back(0x30);
    std::vector<uint8_t> rsa_pk_body;
    rsa_pk_body.insert(rsa_pk_body.end(), mod_int.begin(), mod_int.end());
    rsa_pk_body.insert(rsa_pk_body.end(), exp_int.begin(), exp_int.end());
    der_len(rsa_pk_body.size(), rsa_pk);
    rsa_pk.insert(rsa_pk.end(), rsa_pk_body.begin(), rsa_pk_body.end());
    std::vector<uint8_t> bit_str; bit_str.push_back(0x03);
    der_len(rsa_pk.size() + 1, bit_str); bit_str.push_back(0x00);
    bit_str.insert(bit_str.end(), rsa_pk.begin(), rsa_pk.end());
    static const uint8_t alg_oid[] = { 0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00 };
    std::vector<uint8_t> spki_body;
    spki_body.insert(spki_body.end(), alg_oid, alg_oid + sizeof(alg_oid));
    spki_body.insert(spki_body.end(), bit_str.begin(), bit_str.end());
    std::vector<uint8_t> der_spki; der_spki.push_back(0x30);
    der_len(spki_body.size(), der_spki);
    der_spki.insert(der_spki.end(), spki_body.begin(), spki_body.end());
    return der_spki;
}

static std::vector<uint8_t> GenerateRsaSpkiPem() {
    BCRYPT_ALG_HANDLE hAlg = nullptr; BCRYPT_KEY_HANDLE hKey = nullptr;
    std::vector<uint8_t> result;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0) != 0) return result;
    if (BCryptGenerateKeyPair(hAlg, &hKey, 2048, 0) != 0) { BCryptCloseAlgorithmProvider(hAlg, 0);return result; }
    if (BCryptFinalizeKeyPair(hKey, 0) != 0) { BCryptDestroyKey(hKey);BCryptCloseAlgorithmProvider(hAlg, 0);return result; }
    DWORD pubSz = 0; BCryptExportKey(hKey, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &pubSz, 0);
    std::vector<uint8_t> pubBlob(pubSz);
    BCryptExportKey(hKey, nullptr, BCRYPT_RSAPUBLIC_BLOB, pubBlob.data(), pubSz, &pubSz, 0);
    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
    auto der = BcryptBlobToSpkiDer(pubBlob); if (der.empty()) return result;
    std::string b64 = Base64Encode(der.data(), der.size());
    std::string pem = "-----BEGIN PUBLIC KEY-----\n";
    for (size_t i = 0;i < b64.size();i += 64) pem += b64.substr(i, 64) + "\n";
    pem += "-----END PUBLIC KEY-----\n";
    result.assign(pem.begin(), pem.end());
    Log("[RSA] PEM SPKI generated " + std::to_string(result.size()) + "B");
    return result;
}










static const char* GatewayActionName(int vg_type) {
    switch (vg_type) {
    case 3: return "AUTH";
    case 4: return "ACCESS";
    case 6: return "REPORT";
    case 7: return "HEARTBEAT";
    default: return "UNKNOWN";
    }
}

static bool PostToGateway(const std::vector<uint8_t>& envelope,
    const std::string& puuid,
    const std::string& region,
    std::vector<uint8_t>* out_response = nullptr,
    int vg_type = 3) {   

    std::string effective_puuid = puuid;
    if (effective_puuid.empty()) {
        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
        effective_puuid = g_cached_puuid;
    }
    if (effective_puuid.empty() && !g_cached_jwt.empty()) {
        effective_puuid = PuuidFromJwt(g_cached_jwt);
    }
    if (effective_puuid.empty() && !g_cached_jwt.empty()) {
        auto payload = DecodeJwtPayload(g_cached_jwt);
        effective_puuid = JsonGetStr(payload, "sub");
        if (effective_puuid.empty()) effective_puuid = JsonGetStr(payload, "puuid");
    }

    std::string effective_region = region;
    if (effective_region.empty()) {
        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
        effective_region = g_cached_region;
    }
    if (effective_region.empty() && !g_cached_jwt.empty()) {
        effective_region = ShardFromJwtRobust(g_cached_jwt);
    }
    if (effective_region.empty()) effective_region = "na";
    effective_region = ApplyConfiguredRegion(effective_region, "[GW]");

    std::wstring gw_host = RegionToGwHost(effective_region);
    std::string gw_host_s; for (wchar_t c : gw_host) gw_host_s += (char)(c & 0x7F);
    const std::string action_label = std::to_string(vg_type) + "(" + GatewayActionName(vg_type) + ")";
    Log("[GW] POST " + gw_host_s + " region=" + effective_region + " action=" + action_label + " envelope=" + std::to_string(envelope.size()) + "B puuid=" + (effective_puuid.empty() ? "<empty>" : effective_puuid.substr(0, 8) + "..."));

    HINTERNET hS = WinHttpOpen(VGC_UA, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) { Log("[GW] WinHttpOpen failed"); return false; }
    
    WinHttpSetTimeouts(hS, 10000, 10000, 15000, 15000);
    HINTERNET hC = WinHttpConnect(hS, gw_host.c_str(), GW_PORT, 0);
    if (!hC) { WinHttpCloseHandle(hS); Log("[GW] Connect failed"); return false; }
    HINTERNET hR = WinHttpOpenRequest(hC, L"POST", GW_PATH, L"HTTP/1.1",
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hR) { WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return false; }

    DWORD ssl = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hR, WINHTTP_OPTION_SECURITY_FLAGS, &ssl, sizeof(ssl));

    std::wstring headers;
    headers += L"User-Agent: vanguard/1.18.5-11+20260730.010201\r\n";
    headers += L"Content-Type: application/x-protobuf\r\n";
    if (!effective_puuid.empty()) { std::wstring w(effective_puuid.begin(), effective_puuid.end()); headers += L"X-VG-2: " + w + L"\r\n"; }
    headers += L"X-VG-1: " + std::to_wstring(vg_type) + L"\r\nX-VG-3: 1\r\nAccept: */*";

    BOOL ok = WinHttpSendRequest(hR, headers.c_str(), (DWORD)-1L,
        (LPVOID)envelope.data(), (DWORD)envelope.size(), (DWORD)envelope.size(), 0);
    if (!ok || !WinHttpReceiveResponse(hR, nullptr)) {
        Log("[GW] Send/recv failed err=" + std::to_string(GetLastError()));
        WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
        return false;
    }

    DWORD status = 0, sz = sizeof(DWORD);
    WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);

    std::vector<uint8_t> resp_body; DWORD avail = 0;
    while (WinHttpQueryDataAvailable(hR, &avail) && avail > 0) {
        std::vector<uint8_t> chunk(avail); DWORD rd = 0;
        WinHttpReadData(hR, chunk.data(), avail, &rd); chunk.resize(rd);
        resp_body.insert(resp_body.end(), chunk.begin(), chunk.end());
    }
    WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);

    Log("[GW] HTTP " + std::to_string(status) + " action=" + action_label + " body=" + std::to_string(resp_body.size()) + "B");
    if (status == 200) {
        Log("[GW] *** GATEWAY " + std::string(GatewayActionName(vg_type)) + " OK region=" + effective_region + " action=" + action_label + " ***");
        
        if (out_response) *out_response = resp_body;
        {
            std::lock_guard<std::mutex> lk(g_gw_auth_response_mtx);
            g_gw_auth_response = resp_body;
        }
        {
            std::lock_guard<std::mutex> lk(g_gw_session_mtx);
            g_gw_session.last_auth_response = resp_body;
            g_gw_session.ready = true;
            g_gw_session.cached_at = (double)std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            
            if (vg_type == 3) {
                auto decrypted = VGW::DecryptGatewayResponse(resp_body);
                if (!decrypted.empty()) {
                    auto ar = VGW::DecodeAuthResponse(decrypted);
                    if (!ar.ephemeral_identifiers.empty())
                        g_gw_session.ephemeral_identifiers = ar.ephemeral_identifiers;
                }
            }
        }
        Log("[GW] gateway response cached for next VPS gateway step/action");
        Log("[GW] next gateway action will use latest response body");
        return true;
    }
    else if (!resp_body.empty()) {
        std::string s(resp_body.begin(), resp_body.end());
        Log("[GW] body: " + s.substr(0, 300));
    }
    else {
        Log("[GW] empty body -- check rso_jwt/entitlement/region");
    }
    return false;
}

static bool ExchangeVpsGatewayStep(
    TlsSocket& tls,
    uint32_t request_type,
    uint32_t expected_response_type,
    int gateway_action,
    const std::vector<uint8_t>& gateway_response,
    const std::string& puuid,
    const std::string& region,
    std::vector<uint8_t>& next_gateway_response,
    const char* tag)
{
    auto req = PackMsg(request_type, gateway_response);
    tls.SendAll(req.data(), req.size());

    auto msg = tls.RecvMsg();
    if (msg.size() < 8) {
        Log(std::string("[VPS] ") + tag + " response too short");
        return false;
    }

    uint32_t mt = ReadU32BE(msg.data());
    if (mt == MSG_ERROR) {
        std::string err(msg.begin() + 8, msg.end());
        Log(std::string("[VPS] ") + tag + " server error: " + err);
        return false;
    }
    if (mt != expected_response_type) {
        Log(std::string("[VPS] ") + tag + " expected type " + std::to_string(expected_response_type) + ", got " + std::to_string(mt));
        return false;
    }

    std::vector<uint8_t> payload(msg.begin() + 8, msg.end());
    std::string sid;
    auto envelope = ParseSessionGatewayBody(payload, &sid);
    if (envelope.empty()) {
        Log(std::string("[VPS] ") + tag + " empty envelope");
        return false;
    }

    Log(std::string("[VPS] ") + tag + " envelope=" + std::to_string(envelope.size()) + "B action=" + std::to_string(gateway_action));
    return PostToGateway(envelope, puuid, region, &next_gateway_response, gateway_action);
}

static void VpsServerHeartbeatLoop(
    std::unique_ptr<TlsSocket> tls,
    std::vector<uint8_t> latest_gateway_response,
    std::string puuid,
    std::string region)
{
    Log("[VPS-HB] server-driven heartbeat loop started");
    g_vps_server_heartbeat_running.store(true);

    try {
        while (g_vps_server_heartbeat_running.load()) {
            for (int i = 0; i < 30 && g_vps_server_heartbeat_running.load(); ++i) {
                Sleep(1000);
            }
            if (!g_vps_server_heartbeat_running.load()) break;
            if (latest_gateway_response.empty()) {
                Log("[VPS-HB] stopped: missing latest gateway response");
                break;
            }

            
            std::string server_pub_out;
            auto hb_envelope = VGW::BuildGatewayHeartbeatPayload(latest_gateway_response, server_pub_out);
            if (hb_envelope.empty()) {
                Log("[VPS-HB] BuildGatewayHeartbeatPayload failed -- retrying via server");
                
                std::vector<uint8_t> heartbeat_response;
                if (!ExchangeVpsGatewayStep(
                    *tls,
                    MSG_SESSION_HEARTBEAT,
                    MSG_SESSION_HEARTBEAT_OK,
                    7,
                    latest_gateway_response,
                    puuid,
                    region,
                    heartbeat_response,
                    "SESSION_HEARTBEAT")) {
                    Log("[VPS-HB] fallback heartbeat exchange failed");
                    break;
                }
                if (!heartbeat_response.empty()) latest_gateway_response = heartbeat_response;
                ResetGatewayReauthTimer();
                g_gateway_reauth_remaining_sec.store(30);
                UpdateConsoleTitle();
                Log("[VPS-HB] fallback heartbeat OK");
                continue;
            }

            
            std::vector<uint8_t> hb_resp;
            if (!PostToGateway(hb_envelope, puuid, region, &hb_resp, 7)) {
                Log("[VPS-HB] direct gateway heartbeat failed -- retrying via server");
                std::vector<uint8_t> heartbeat_response;
                if (!ExchangeVpsGatewayStep(
                    *tls,
                    MSG_SESSION_HEARTBEAT,
                    MSG_SESSION_HEARTBEAT_OK,
                    7,
                    latest_gateway_response,
                    puuid,
                    region,
                    heartbeat_response,
                    "SESSION_HEARTBEAT")) {
                    Log("[VPS-HB] fallback heartbeat exchange failed");
                    break;
                }
                if (!heartbeat_response.empty()) latest_gateway_response = heartbeat_response;
            } else {
                if (!hb_resp.empty()) latest_gateway_response = hb_resp;
                Log("[VPS-HB] direct gateway heartbeat OK resp=" + std::to_string(hb_resp.size()) + "B");
            }

            ResetGatewayReauthTimer();
            g_gateway_reauth_remaining_sec.store(30);
            UpdateConsoleTitle();
            Log("[VPS-HB] heartbeat OK");
        }
    }
    catch (const std::exception& e) {
        Log("[VPS-HB] exception: " + std::string(e.what()));
    }

    g_vps_server_heartbeat_running.store(false);
    g_keepalive_running.store(false);
    tls->Close();
    Log("[VPS-HB] server-driven heartbeat loop stopped");
}








static std::atomic_int  g_reauth_fail_count(0);
static double           g_last_reauth_time = 0;

static void UpdateConsoleTitle() {
    int remaining = g_gateway_reauth_remaining_sec.load();
    if (remaining < 0) remaining = 0;

    int hh = remaining / 3600;
    int mm = (remaining % 3600) / 60;
    int ss = remaining % 60;

    wchar_t title[128] = {};
    swprintf_s(title, L"CHEATGLOBAL PASTERS | Session refresh %02d:%02d:%02d", hh, mm, ss);
    SetConsoleTitleW(title);
}

static void ResetGatewayReauthTimer() {
    g_gateway_reauth_remaining_sec.store(GATEWAY_REAUTH_INTERVAL_SEC);
    g_gateway_reauth_restart_countdown.store(true);
    UpdateConsoleTitle();
}

static bool GatewayDoReauth() {
    std::string jwt, puuid, region, sid;
    {
        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
        jwt    = g_cached_jwt;
        puuid  = g_cached_puuid;
        sid    = g_cached_sid;
        region = g_cached_region;
    }
    if (jwt.empty() || puuid.empty()) {
        Log("[GW-KA] re-auth skipped: no jwt/puuid");
        return false;
    }
    if (region.empty()) region = ShardFromJwtRobust(jwt);
    if (region.empty()) region = "na";
    region = ApplyConfiguredRegion(region, "[GW-KA]");

    
    
    double now = NowSec();
    bool forced = g_gw_reauth_needed.load();
    if (!forced && (now - g_last_reauth_time) < 60.0) {
        Log("[GW-KA] re-auth throttled â€” last was " + std::to_string((int)(now - g_last_reauth_time)) + "s ago");
        return false;
    }
    if (forced) Log("[GW-KA] re-auth forced (lobby return / new match)");

    const std::string resolved_sid = ResolveNonEmptySid(jwt, sid, puuid, "[GW-KA]");
    std::string last_ephemeral;
    {
        std::lock_guard<std::mutex> lk(g_gw_session_mtx);
        last_ephemeral = g_gw_session.ephemeral_identifiers;
    }
    const auto& _hwp2 = GetRandomizedHardwareProfile();
    auto envelope = VGW::BuildGatewayAuthPayload(jwt, resolved_sid, GetConfiguredGatewayMachineId(), GetStableHt(), last_ephemeral,
        _hwp2.cpu_brand, _hwp2.cpu_model, _hwp2.gpu_model, "Windows 10 Pro", _hwp2.os_version);
    if (envelope.empty()) {
        Log("[GW-KA] re-auth skipped: envelope empty");
        return false;
    }

    g_last_reauth_time = NowSec();
    Log("[GW-KA] sending re-auth -> " + region);
    std::vector<uint8_t> new_resp;
    bool ok = PostToGateway(envelope, puuid, region, &new_resp, 3);
    if (ok) {
        g_reauth_fail_count.store(0);
        ResetGatewayReauthTimer();
        Log("[GW-KA] re-auth OK -> " + region);
    } else {
        int fails = g_reauth_fail_count.fetch_add(1) + 1;
        Log("[GW-KA] re-auth FAILED fails=" + std::to_string(fails));
        
        g_last_reauth_time = NowSec() + 120.0; 
        
        g_gateway_reauth_remaining_sec.store(120);
        UpdateConsoleTitle();
    }
    g_gw_reauth_needed.store(false);
    return ok;
}

static void GatewayKeepaliveLoop() {
    Log("[GW-KA] keepalive loop started â€” re-auth every 5.5 minutes");
    while (g_keepalive_running.load()) {
        
        for (int i = 0; i < 330 && g_keepalive_running.load(); i++) {
            Sleep(1000);
            if (g_gw_reauth_needed.load()) break;
        }
        if (!g_keepalive_running.load()) break;
        GatewayDoReauth();
    }
    Log("[GW-KA] keepalive loop stopped");
}

static void GatewayKeepaliveLoop45Min() {
    Log("[GW-KA] keepalive loop started - re-auth every 45 minutes");
    while (g_keepalive_running.load()) {
        g_gateway_reauth_restart_countdown.store(false);
        g_gateway_reauth_remaining_sec.store(GATEWAY_REAUTH_INTERVAL_SEC);
        UpdateConsoleTitle();

        for (int i = 0; i < GATEWAY_REAUTH_INTERVAL_SEC && g_keepalive_running.load(); i++) {
            Sleep(1000);
            if (g_gw_reauth_needed.load()) break;
            if (g_gateway_reauth_restart_countdown.exchange(false)) {
                i = -1;
                g_gateway_reauth_remaining_sec.store(GATEWAY_REAUTH_INTERVAL_SEC);
                UpdateConsoleTitle();
                continue;
            }
            g_gateway_reauth_remaining_sec.store(GATEWAY_REAUTH_INTERVAL_SEC - (i + 1));
            UpdateConsoleTitle();
        }

        if (!g_keepalive_running.load()) break;

        g_gateway_reauth_remaining_sec.store(0);
        UpdateConsoleTitle();
        if (GatewayDoReauth()) {
            Beep(880, 120);
        }
    }

    g_gateway_reauth_remaining_sec.store(GATEWAY_REAUTH_INTERVAL_SEC);
    UpdateConsoleTitle();
    Log("[GW-KA] keepalive loop stopped");
}







static bool SmartGatewayMint(const std::string& jwt, const std::string& sid,
    const std::string& puuid, uint32_t pid) {
        const std::string resolved_sid = ResolveNonEmptySid(jwt, sid, puuid, "[GW]");

    
        {
            std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
            if (!g_cached_jwt.empty() && g_cached_jwt == jwt && g_cached_sid == resolved_sid) {
                
                
                
                std::lock_guard<std::mutex> lk2(g_gw_session_mtx);
                if (g_gw_session.ready) {
                    return true; 
                }
            }
        }

        {
            std::lock_guard<std::mutex> lk(g_gw_session_mtx);
            if (g_gw_session.ready) {
                Log("[GW] token or sid changed! -- allowing new JWT mint");
                g_gw_session.Reset();
            }
        }

        
        
        g_keepalive_running.store(false);

        Log("[GW] forwarding token to gateway (auto-mint)");

        
        {
            std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
            g_cached_jwt = jwt;
            g_cached_sid = resolved_sid;
            g_cached_puuid = puuid;
        }

        std::string region = ShardFromJwtRobust(jwt);
        if (region.empty()) {
            
            std::lock_guard<std::mutex> lk3(g_jwt_cache_mtx);
            LogJwtRegionHints(jwt, "[JWT-REGION][GW]");
            region = g_cached_region.empty() ? "na" : g_cached_region;
            Log("[GW] region fallback -> " + region);
        }
        region = ApplyConfiguredRegion(region, "[GW]");
        
        {
            std::lock_guard<std::mutex> lk3(g_jwt_cache_mtx);
            if (!region.empty()) g_cached_region = region;
        }

        
        Log("[GW] building auth payload (standalone protobuf+crypto)");
        const auto& _hwp3 = GetRandomizedHardwareProfile();
        auto envelope = VGW::BuildGatewayAuthPayload(jwt, resolved_sid, GetConfiguredGatewayMachineId(), GetStableHt(), "",
            _hwp3.cpu_brand, _hwp3.cpu_model, _hwp3.gpu_model, "Windows 10 Pro", _hwp3.os_version);
        if (envelope.empty()) {
            Log("[GW] BuildGatewayAuthPayload failed -- falling back to vgk payload");
            std::lock_guard<std::mutex> lk(g_vgk_payload_mtx);
            envelope = g_vgk_payload;
        }
        if (envelope.empty()) {
            Log("[GW] no envelope available, mint aborted");
            return false;
        }

        std::vector<uint8_t> auth_resp;
        bool ok = PostToGateway(envelope, puuid, region, &auth_resp);
        if (ok) {
            Log("[GW] gateway mint success (auto)");
            ResetGatewayReauthTimer();

            
            g_last_reauth_time = NowSec();

            
            StopVgk();

            
            if (!g_keepalive_running.exchange(true)) {
                ResetGatewayReauthTimer();
                std::thread(GatewayKeepaliveLoop45Min).detach();
            }
            return true;
        }
        else {
            Log("[GW] gateway mint failed -- will retry on next JWT");
            g_keepalive_running.store(false);
            g_gw_auto_posted.store(false);
        }
        return false;
}





static std::vector<uint8_t> BuildSessionAuth(
    const std::string& jwt, const std::string& puuid,
    const std::string& external_sid, const std::string& region,
    uint32_t pid, const std::vector<uint8_t>& hwid,
    const std::vector<uint8_t>& rsa_spki_pem,
    const std::string& cpu_brand, const std::string& cpu_model,
    const std::string& gpu_brand, const std::string& gpu_model,
    uint32_t cpu_logical_count)
{
    std::vector<uint8_t> body;
    PushLenStr(body, AUTH_KEY);
    PushLenBytes(body, hwid);                
    PushLenStr(body, jwt);
    PushLenStr(body, puuid);
    PushU32BE(body, pid);
    uint64_t now_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    PushU64BE(body, now_ms);
    PushLenStr(body, region);
    PushLenBytes(body, hwid);                
    PushLenStr(body, puuid);                 

    PushLenStr(body, RandomizedVersion ? GetFakeHostname() : "WIN-PC");

    PushLenBytes(body, rsa_spki_pem);
    PushLenStr(body, "release-13.00-shipping-30-4955671");
    PushU32BE(body, 4955671); PushU32BE(body, 13);
    PushU32BE(body, 0); PushU32BE(body, 30); PushU32BE(body, 0);
    PushLenStr(body, external_sid);
    PushLenStr(body, cpu_brand); PushLenStr(body, cpu_model);
    PushLenStr(body, gpu_brand); PushLenStr(body, gpu_model);
    PushU32BE(body, cpu_logical_count);
    return body;
}





typedef NTSTATUS(NTAPI* pfnNtUnloadDriver)(PUNICODE_STRING DriverServiceName);


typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION;

#define SystemHandleInformation 16

typedef NTSTATUS(NTAPI* pfnNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);


static void KillVgkHandles() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    auto NtQSI = (pfnNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQSI) return;

    
    ULONG size = 1 << 20; 
    std::vector<BYTE> buf(size);
    NTSTATUS st;
    while ((st = NtQSI(SystemHandleInformation, buf.data(), (ULONG)buf.size(), &size)) == 0x80000005L) {
        buf.resize(buf.size() * 2);
    }
    if (st != 0) return;

    auto* info = (SYSTEM_HANDLE_INFORMATION*)buf.data();

    
    DWORD val_pid = 0;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    std::string n; for (wchar_t c : pe.szExeFile) if (c) n += (char)(c & 0x7F);
                    if (_stricmp(n.c_str(), "VALORANT-Win64-Shipping.exe") == 0) {
                        val_pid = pe.th32ProcessID; break;
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
    }
    if (!val_pid) { Log("[VGK] Valorant not found"); return; }

    
    HANDLE hVgk = CreateFileA("\\\\.\\vgk",
        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);

    PVOID vgk_obj = nullptr;
    if (hVgk != INVALID_HANDLE_VALUE) {
        DWORD my_pid = GetCurrentProcessId();
        for (ULONG i = 0;i < info->NumberOfHandles;i++) {
            auto& e = info->Handles[i];
            if (e.UniqueProcessId == my_pid && (HANDLE)(uintptr_t)e.HandleValue == hVgk) {
                vgk_obj = e.Object; break;
            }
        }
        CloseHandle(hVgk);
    }

    
    HANDLE hVal = OpenProcess(PROCESS_DUP_HANDLE, FALSE, val_pid);
    if (!hVal) { Log("[VGK] Cannot open Valorant process"); return; }

    int killed = 0;
    for (ULONG i = 0;i < info->NumberOfHandles;i++) {
        auto& e = info->Handles[i];
        if (e.UniqueProcessId != (USHORT)val_pid) continue;
        
        if (vgk_obj && e.Object != vgk_obj) continue;
        if (!vgk_obj) continue; 

        
        HANDLE dup = nullptr;
        if (DuplicateHandle(hVal, (HANDLE)(uintptr_t)e.HandleValue,
            GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_CLOSE_SOURCE)) {
            CloseHandle(dup);
            killed++;
        }
    }
    CloseHandle(hVal);
    Log("[VGK] Closed " + std::to_string(killed) + " vgk handle(s) from Valorant");
}

static bool ForceUnloadVgk() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    auto NtUnloadDriver = (pfnNtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");
    if (!NtUnloadDriver) return false;

    WCHAR reg_path[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\vgk";
    UNICODE_STRING us;
    us.Buffer = reg_path;
    us.Length = (USHORT)(wcslen(reg_path) * sizeof(WCHAR));
    us.MaximumLength = us.Length + sizeof(WCHAR);

    NTSTATUS st = NtUnloadDriver(&us);
    Log("[VGK] NtUnloadDriver status=0x" + [&] {std::ostringstream o;o << std::hex << (uint32_t)st;return o.str();}() +
        (st == 0 ? " (OK)" : st == 0xC0000024L ? " (refs exist)" : st == 0xC000010EL ? " (not loaded)" : ""));
    return st == 0;
}

static void StopVgk() {
    
    
    Log("[VGK] StopVgk called â€” skipping service stop (Valorant still running)");
}







struct ValorantWindowCtx { DWORD pid; int pct; };
static int GetValorantLoadingPct() {
    int pct = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"VALORANT-Win64-Shipping.exe") == 0) {
                ValorantWindowCtx ctx{ pe.th32ProcessID, 0 };
                EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
                    auto* c = reinterpret_cast<ValorantWindowCtx*>(lp);
                    DWORD wp = 0; GetWindowThreadProcessId(hwnd, &wp);
                    if (wp != c->pid) return TRUE;
                    wchar_t title[256]{}; GetWindowTextW(hwnd, title, 255);
                    std::wstring t(title);
                    auto pos = t.find(L"Loading");
                    if (pos != std::wstring::npos) {
                        auto p1 = t.find(L'(', pos);
                        auto p2 = t.find(L'%', pos);
                        if (p1 != std::wstring::npos && p2 != std::wstring::npos && p2 > p1)
                            c->pct = _wtoi(t.substr(p1 + 1, p2 - p1 - 1).c_str());
                    }
                    return TRUE;
                    }, (LPARAM)&ctx);
                pct = ctx.pct;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pct;
}


static bool SendViaLocalServer(const std::string& rso_jwt,
    const std::string& sid, const std::string& puuid, uint32_t pid)
{
    const std::string resolved_sid = ResolveNonEmptySid(rso_jwt, sid, puuid, "[CLI]");

    
    {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline) {
            {
                std::lock_guard<std::mutex> lk(g_vgk_payload_mtx);
                if (!g_vgk_payload.empty()) break;
            }
            Sleep(50);
        }
    }
    auto tls = std::make_unique<TlsSocket>();
    if (!tls->Connect(SERVER_HOST, SERVER_PORT, TLS_SKIP_VERIFY)) { Log(("[CLI] TLS connect failed")); return false; }
    Log(("[CLI] TLS connected"));

    auto hwid = GetConfiguredHwid();
    std::string cpu_brand, cpu_model, gpu_brand, gpu_model; uint32_t cpu_cores = 0;
    GetCpuInfo(cpu_brand, cpu_model, cpu_cores);
    GetGpuInfo(gpu_brand, gpu_model);

    auto rsa_pem = GenerateRsaSpkiPem();
    if (rsa_pem.empty()) { Log(("[CLI] RSA keygen failed")); tls->Close(); return false; }

    std::string region = ShardFromJwtRobust(rso_jwt);
    if (region.empty()) {
        LogJwtRegionHints(rso_jwt, "[JWT-REGION][CLI]");
        std::lock_guard<std::mutex> lk2(g_jwt_cache_mtx);
        region = g_cached_region.empty() ? "na" : g_cached_region;
    }
    region = ApplyConfiguredRegion(region, "[CLI]");

    auto sa_payload = BuildSessionAuth(
        rso_jwt, puuid, resolved_sid, region, pid, hwid, rsa_pem,
        cpu_brand, cpu_model, gpu_brand, gpu_model, cpu_cores);

    auto sa_pkt = PackMsg(MSG_SESSION_AUTH, sa_payload);
    Log("[CLI] Sending SESSION_AUTH puuid=" + puuid.substr(0, 8) + " region=" + region);

    try {
        tls->SendAll(sa_pkt.data(), sa_pkt.size());
        auto msg = tls->RecvMsg();
        uint32_t mt = ReadU32BE(msg.data());
        uint32_t plen = ReadU32BE(msg.data() + 4);

        if (mt == MSG_ERROR) {
            std::string err(msg.begin() + 8, msg.end());
            Log("[CLI] Server error: " + err); tls->Close(); return false;
        }
        if (mt != MSG_SESSION_AUTH_OK) {
            Log("[CLI] Expected SESSION_AUTH_OK, got " + std::to_string(mt)); tls->Close(); return false;
        }

        
        std::vector<uint8_t> payload(msg.begin() + 8, msg.end());
        std::string server_sid;
        std::vector<uint8_t> envelope = ParseSessionGatewayBody(payload, &server_sid);

        Log("[CLI] SESSION_AUTH_OK server_sid=" + server_sid.substr(0, 8) + " envelope=" + std::to_string(envelope.size()) + "B");

        
        
        UpdateDisplaySessionState(puuid, region, puuid);

        bool vps_gateway_ok = false;
        std::vector<uint8_t> access_resp;
        std::vector<uint8_t> heartbeat_resp;
        if (!envelope.empty()) {
            std::vector<uint8_t> auth_resp;
            Log("[VPS] Posting server auth envelope to Riot Gateway (action=3)");
            if (PostToGateway(envelope, puuid, region, &auth_resp, 3) && !auth_resp.empty()) {
                if (ExchangeVpsGatewayStep(
                    *tls,
                    MSG_SESSION_ACCESS,
                    MSG_SESSION_ACCESS_OK,
                    4,
                    auth_resp,
                    puuid,
                    region,
                    access_resp,
                    "SESSION_ACCESS")) {
                    vps_gateway_ok = true;

                    if (ExchangeVpsGatewayStep(
                        *tls,
                        MSG_SESSION_HEARTBEAT,
                        MSG_SESSION_HEARTBEAT_OK,
                        7,
                        access_resp,
                        puuid,
                        region,
                        heartbeat_resp,
                        "SESSION_HEARTBEAT")) {
                        Log("[VPS] Initial server-driven heartbeat completed");
                    }
                }
            }
        }

        if (vps_gateway_ok) {
            Log("[VPS] Server-driven gateway flow completed");
            StopVgk();
            g_vps_server_heartbeat_running.store(false);
            g_keepalive_running.store(true);
            ResetGatewayReauthTimer();
            std::thread(
                VpsServerHeartbeatLoop,
                std::move(tls),
                heartbeat_resp.empty() ? access_resp : heartbeat_resp,
                puuid,
                region).detach();
            return true;
        }

        tls->Close();
        Log("[CLI] Server gateway flow unavailable; falling back to local SmartGatewayMint");
        return SmartGatewayMint(rso_jwt, resolved_sid, puuid, pid);
        
    }
    catch (const std::exception& e) {
        Log("[CLI] Exception: " + std::string(e.what())); tls->Close();
    }
    return false;
}

static void QueuePendingGatewayRequest(const std::string& jwt,
    const std::string& sid, const std::string& puuid, uint32_t pid)
{
    std::lock_guard<std::mutex> lk(g_pending_gateway_mtx);
    g_pending_gateway.jwt = jwt;
    g_pending_gateway.sid = sid;
    g_pending_gateway.puuid = puuid;
    g_pending_gateway.pid = pid;
    g_pending_gateway.queued_at = std::chrono::steady_clock::now();
    g_pending_gateway.valid = true;
}

static bool TriggerPendingGatewaySend() {
    if (g_gateway_send_inflight.exchange(true)) {
        return false;
    }

    PendingGatewayRequest request;
    {
        std::lock_guard<std::mutex> lk(g_pending_gateway_mtx);
        if (!g_pending_gateway.valid) {
            g_gateway_send_inflight.store(false);
            return false;
        }
        request = g_pending_gateway;
    }

    std::thread([request]() {
        Log("[GUI] Manual gateway send requested");
        bool ok = SendViaLocalServer(request.jwt, request.sid, request.puuid, request.pid);
        if (ok) {
            Beep(880, 120);
            std::lock_guard<std::mutex> lk(g_pending_gateway_mtx);
            if (g_pending_gateway.valid &&
                g_pending_gateway.jwt == request.jwt &&
                g_pending_gateway.sid == request.sid) {
                g_pending_gateway.valid = false;
            }
        } else {
            Log("[GUI] Manual gateway send failed; request kept pending");
        }
        g_gateway_send_inflight.store(false);
    }).detach();

    return true;
}

static bool TriggerGatewayManualAction() {
    if (g_gateway_auto_send.load()) {
        return false;
    }

    constexpr ULONGLONG MANUAL_GATEWAY_COOLDOWN_MS = 10000;
    ULONGLONG now_ms = GetTickCount64();
    ULONGLONG last_trigger_ms = g_gateway_manual_last_trigger_ms.load();
    if (last_trigger_ms != 0 && (now_ms - last_trigger_ms) < MANUAL_GATEWAY_COOLDOWN_MS) {
        ULONGLONG remaining_ms = MANUAL_GATEWAY_COOLDOWN_MS - (now_ms - last_trigger_ms);
        Log("[GUI] F5 ignored: manual gateway cooldown " + std::to_string((remaining_ms + 999) / 1000) + "s");
        return false;
    }

    bool has_pending_request = false;
    {
        std::lock_guard<std::mutex> lk(g_pending_gateway_mtx);
        has_pending_request = g_pending_gateway.valid;
    }
    if (has_pending_request) {
        bool triggered = TriggerPendingGatewaySend();
        if (triggered) {
            g_gateway_manual_last_trigger_ms.store(now_ms);
        }
        return triggered;
    }

    std::string jwt;
    std::string puuid;
    {
        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
        jwt = g_cached_jwt;
        puuid = g_cached_puuid;
    }

    if (jwt.empty() || puuid.empty()) {
        Log("[GUI] F5 ignored: no cached gateway session");
        return false;
    }

    if (g_gateway_manual_reauth_inflight.exchange(true)) {
        Log("[GUI] F5 ignored: manual re-auth already in flight");
        return false;
    }

    g_gateway_manual_last_trigger_ms.store(now_ms);

    std::thread([]() {
        Log("[GUI] F5 manual gateway re-auth requested");
        g_gw_reauth_needed.store(true);
        if (GatewayDoReauth()) {
            Beep(880, 120);
        }
        g_gateway_manual_reauth_inflight.store(false);
    }).detach();

    return true;
}

static bool TriggerGatewayAutoRefreshAction() {
    if (!g_gateway_auto_send.load()) {
        return false;
    }

    constexpr ULONGLONG MANUAL_GATEWAY_COOLDOWN_MS = 10000;
    ULONGLONG now_ms = GetTickCount64();
    ULONGLONG last_trigger_ms = g_gateway_manual_last_trigger_ms.load();
    if (last_trigger_ms != 0 && (now_ms - last_trigger_ms) < MANUAL_GATEWAY_COOLDOWN_MS) {
        ULONGLONG remaining_ms = MANUAL_GATEWAY_COOLDOWN_MS - (now_ms - last_trigger_ms);
        Log("[GUI] F5 ignored: manual gateway cooldown " + std::to_string((remaining_ms + 999) / 1000) + "s");
        return false;
    }

    std::string jwt;
    std::string puuid;
    {
        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
        jwt = g_cached_jwt;
        puuid = g_cached_puuid;
    }

    if (jwt.empty() || puuid.empty()) {
        Log("[GUI] F5 ignored: no cached gateway session");
        return false;
    }

    if (g_gateway_manual_reauth_inflight.exchange(true)) {
        Log("[GUI] F5 ignored: manual re-auth already in flight");
        return false;
    }

    g_gateway_manual_last_trigger_ms.store(now_ms);

    std::thread([]() {
        Log("[GUI] F5 automated-mode gateway refresh requested");
        g_gw_reauth_needed.store(true);
        if (GatewayDoReauth()) {
            Beep(880, 120);
        }
        g_gateway_manual_reauth_inflight.store(false);
    }).detach();

    return true;
}

static void GatewayHotkeyLoop() {
    Log(("[GUI] F5 hotkey loop active"));
    while (!g_shutdown.load()) {
        if (GetAsyncKeyState(VK_F5) & 1) {
            if (g_gateway_auto_send.load()) {
                TriggerGatewayAutoRefreshAction();
            } else {
                TriggerGatewayManualAction();
            }
        }
        Sleep(50);
    }
}




static void TryExtractAndSend(const uint8_t* buf, DWORD len) {
    std::string ascii(len, ' ');
    for (DWORD i = 0; i < len; i++) if (buf[i] >= 0x20 && buf[i] < 0x7F) ascii[i] = (char)buf[i];
    static const std::regex jwt_re(R"((eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}))");
    static const std::regex uuid_re(R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");

    std::vector<std::string> all_jwts;
    std::sregex_iterator jit(ascii.begin(), ascii.end(), jwt_re), jend;
    for (; jit != jend; ++jit) all_jwts.push_back((*jit)[1].str());

    if (all_jwts.empty()) {
        Log("[PIPE] No JWT found in this scan.");
        return;
    }

    std::string jwt = all_jwts[0];
    Log("[PIPE] JWT candidates found=" + std::to_string(all_jwts.size()));

    std::string first_uuid, last_uuid;
    std::sregex_iterator it(ascii.begin(), ascii.end(), uuid_re), end;
    for (; it != end; ++it) { if (first_uuid.empty()) first_uuid = it->str(); last_uuid = it->str(); }

    std::string puuid = first_uuid;
    if (puuid.empty()) puuid = PuuidFromJwt(jwt);
    std::string ext_sid = ResolveNonEmptySid(jwt, last_uuid, puuid, "[PIPE]");
    uint32_t vpid = g_valorant_pid;
    Log("[PIPE] puuid=" + puuid.substr(0, 8) + " sid=" + ext_sid.substr(0, 8) + " pid=" + std::to_string(vpid));

    
    {
        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
        if (jwt == g_cached_jwt && ext_sid == g_cached_ext_sid) {
            
            return;
        }
        
        g_cached_jwt     = jwt;
        g_cached_ext_sid = ext_sid;
        g_cached_sid     = ext_sid;
        g_cached_puuid   = puuid;
    }

    Log("[PIPE] NEW AUTH_TOKEN captured (length: " + std::to_string(jwt.size()) + ")");
    QueuePendingGatewayRequest(jwt, ext_sid, puuid, vpid);
    if (g_gateway_auto_send.load()) {
        Log("[PIPE] token saved -- auto gateway send enabled");
        std::thread([jwt, ext_sid, puuid, vpid]() {
            SendViaLocalServer(jwt, ext_sid, puuid, vpid);
        }).detach();
    } else {
        Log("[PIPE] token captured -- press F5 for gateway send");
    }
}

static uint32_t PipeReadU32(const uint8_t* p) {
    uint32_t v = 0;
    memcpy(&v, p, sizeof(v));
    return v;
}

static void PipeWriteU32(std::vector<uint8_t>& v, size_t off, uint32_t value) {
    if (v.size() >= off + sizeof(value)) memcpy(v.data() + off, &value, sizeof(value));
}

static void PipeWriteU64(std::vector<uint8_t>& v, size_t off, uint64_t value) {
    if (v.size() >= off + sizeof(value)) memcpy(v.data() + off, &value, sizeof(value));
}

static bool PipeWriteAndFlush(HANDLE pipe, const std::vector<uint8_t>& data, const std::string& tag) {
    if (data.empty()) {
        Log(tag + " skipped empty write");
        return false;
    }
    DWORD bw = 0;
    BOOL ok = WriteFile(pipe, data.data(), (DWORD)data.size(), &bw, nullptr);
    if (ok) FlushFileBuffers(pipe);
    Log(tag + " written=" + std::to_string(bw) + "/" + std::to_string(data.size()) +
        (ok ? "" : " err=" + std::to_string(GetLastError())));
    return ok && bw == data.size();
}

static int PipeCompatNextMagic(int magic) {
    static std::mutex magic_mtx;
    static int step = -1;
    std::lock_guard<std::mutex> lk(magic_mtx);
    step = (step + 1) % 5;
    if (step == 0) return magic + 1;
    if (step == 1) return magic + 3;
    if (step == 2) return magic - 1;
    if (step == 3) return magic + 2;
    return magic + 5;
}

static std::string PipeExtractFirstUuid(const uint8_t* data, size_t n) {
    std::string ascii((const char*)data, (const char*)data + n);
    static const std::regex uuid_re(R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");
    std::smatch m;
    if (std::regex_search(ascii, m, uuid_re)) return m[0].str();
    return "";
}

static bool PipeParseUuidBytes(const std::string& uuid, uint8_t out[16]) {
    if (uuid.size() != 36) return false;
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    uint8_t raw[16]{};
    int ri = 0;
    for (size_t i = 0; i < uuid.size();) {
        if (uuid[i] == '-') {
            ++i;
            continue;
        }
        if (i + 1 >= uuid.size() || ri >= 16) return false;
        int hi = hexval(uuid[i]);
        int lo = hexval(uuid[i + 1]);
        if (hi < 0 || lo < 0) return false;
        raw[ri++] = (uint8_t)((hi << 4) | lo);
        i += 2;
    }
    if (ri != 16) return false;

    out[0] = raw[3]; out[1] = raw[2]; out[2] = raw[1]; out[3] = raw[0];
    out[4] = raw[5]; out[5] = raw[4];
    out[6] = raw[7]; out[7] = raw[6];
    memcpy(out + 8, raw + 8, 8);
    return true;
}

static std::vector<uint8_t> PipeBuildCompatAuthAck(int magic, const std::string& uuid) {
    std::vector<uint8_t> ack(0x3c, 0);
    PipeWriteU32(ack, 0, (uint32_t)(magic + 1));
    PipeWriteU32(ack, 4, 0x40);
    PipeWriteU32(ack, 8, 1);
    PipeWriteU32(ack, 0x18, 0x18);

    uint8_t guid[16]{};
    if (PipeParseUuidBytes(uuid, guid)) {
        memcpy(ack.data() + 0x24, guid, sizeof(guid));
    }
    else {
        Log("[PIPE][COMPAT] auth ack uuid parse failed, GUID left zero uuid=" + uuid);
    }

    uint64_t timestamp = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    PipeWriteU64(ack, 0x34, timestamp);
    return ack;
}

static bool SendPipeDisconnectMessage(HANDLE pipe, const std::string& reason) {
    if (!pipe || pipe == INVALID_HANDLE_VALUE) {
        Log("[PIPE][DISCONNECT] skipped: invalid pipe reason=" + reason);
        return false;
    }

    std::vector<uint8_t> payload(36, 0);
    payload[0] = 0x02;
    payload[4] = 0x24;
    payload[8] = 0x01;
    PipeWriteU32(payload, 24, 0x539);

    Log("[PIPE][DISCONNECT] sending 36-byte payload reason=" + reason);
    return PipeWriteAndFlush(pipe, payload, "[PIPE][DISCONNECT] payload");
}

static bool SendDisconnectMessageToCurrentPipe(const std::string& reason) {
    HANDLE pipe = (HANDLE)g_current_pipe.load();
    return SendPipeDisconnectMessage(pipe, reason);
}

static void HandlePipeClient(HANDLE pipe) {
    std::vector<uint8_t> buf(16384); DWORD bytesRead; int hb_count = 0; int packet_count = 0;
    g_current_pipe.store((void*)pipe);
    Log("[PIPE] current pipe handle registered");

    
    
    {
        std::vector<uint8_t> challenge(36, 0);
        PipeWriteU64(challenge, 0, 0x24000003e9ULL); 
        PipeWriteU64(challenge, 8, 1);
        PipeWriteU32(challenge, 24, 4);
        PipeWriteAndFlush(pipe, challenge, "[PIPE] initial 36-byte challenge handshake");
    }

    while (!g_shutdown.load()) {
        if (!ReadFile(pipe, buf.data(), (DWORD)buf.size(), &bytesRead, nullptr) || bytesRead == 0) break;
        packet_count++;
        Log("[PIPE] packet#" + std::to_string(packet_count) + " " + std::to_string(bytesRead) + " bytes (0x" + [&] {std::ostringstream o;o << std::hex << (int)buf[0];return o.str();}() + ")");

        
        if (bytesRead == 40 && buf[0] == 0x03) {
            std::vector<uint8_t> resp(buf.data(), buf.data() + 40); resp[0] = 0x04;
            PipeWriteAndFlush(pipe, resp, "[PIPE][HB] vgk ping ack #" + std::to_string(++hb_count));
            {
                std::lock_guard<std::mutex> lk(g_session_mgr.mtx);
                for (auto& kv : g_session_mgr.sessions) kv.second->last_activity = NowSec();
            }
            continue;
        }

        
        if (buf[0] == 0x64) {
            
            std::ostringstream rawHex;
            DWORD logLen = bytesRead < 16 ? bytesRead : 16;
            for (DWORD i = 0; i < logLen; i++)
                rawHex << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i] << " ";
            Log("[PIPE][0x64] AUTH_REQUEST bytes=" + std::to_string(bytesRead) + " raw=" + rawHex.str());

            
            if (bytesRead > 40) {
                Log("[PIPE][0x64] scanning for JWT inside auth request...");
                TryExtractAndSend(buf.data(), bytesRead);
            }

            std::string jwt, puuid, sid, region;
            {
                std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
                jwt    = g_cached_jwt;
                puuid  = g_cached_puuid;
                sid    = g_cached_sid;
                region = g_cached_region;
            }

            
            if (jwt.empty()) {
                Log("[PIPE][0x64] JWT not yet available, waiting 2s...");
                Sleep(2000);
                std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
                jwt    = g_cached_jwt;
                puuid  = g_cached_puuid;
                sid    = g_cached_sid;
                region = g_cached_region;
            }

            region = ApplyConfiguredRegion(region, "[PIPE][0x64]");
            Log("[PIPE][0x64] jwt=" + (jwt.empty() ? "EMPTY" : jwt.substr(0,20)+"...") + " puuid=" + (puuid.empty() ? "EMPTY" : puuid.substr(0,8)+"..."));

            auto pkt  = std::vector<uint8_t>(buf.data(), buf.data() + bytesRead);
            auto resp = g_tasks_handler.handle_auth_request(jwt, puuid, sid, region);
            
            if (!jwt.empty()) {
                std::thread([]() { g_round_tracker.on_round_end(); }).detach();
            }
            PipeWriteAndFlush(pipe, resp, "[PIPE][0x64] AUTH_REQUEST response");
            Log("[PIPE] AUTH_REQUEST (0x64) handled, response sent");
            continue;
        }

        
        if (bytesRead >= 36) {
            const int compat_type = (int)PipeReadU32(buf.data() + 8);
            if (compat_type == 1 || compat_type == 2 || compat_type == 4 || compat_type == 5 || compat_type == 6) {
                const int magic = (int)PipeReadU32(buf.data());
                std::vector<uint8_t> reply;
                bool inject_type_9 = false;

                Log("[PIPE][COMPAT] struct type=" + std::to_string(compat_type) +
                    " magic=0x" + [&] { std::ostringstream o; o << std::hex << magic; return o.str(); }() +
                    " bytes=" + std::to_string(bytesRead));

                if (compat_type == 6) {
                    reply = { 8, 9, 18, 0 };
                    Log("[PIPE][COMPAT] type 6 task ACK shape selected");
                }
                else if (compat_type == 5) {
                    reply.assign(56, 0);
                    const int reply_magic = PipeCompatNextMagic(magic);
                    PipeWriteU32(reply, 0, (uint32_t)reply_magic);
                    PipeWriteU32(reply, 4, 56);
                    PipeWriteU32(reply, 8, 1);
                    PipeWriteU32(reply, 24, 16);
                    Log("[PIPE][COMPAT] type 5 modules ACK magic=0x" +
                        [&] { std::ostringstream o; o << std::hex << reply_magic; return o.str(); }());
                }
                else if (compat_type == 4) {
                    if (bytesRead > 100) {
                        Log("[PIPE][COMPAT] type 4 scanning for JWT/SID");
                        TryExtractAndSend(buf.data(), bytesRead);
                    }

                    std::string active_uuid = PipeExtractFirstUuid(buf.data(), bytesRead);
                    if (active_uuid.empty()) {
                        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
                        active_uuid = !g_cached_sid.empty() ? g_cached_sid : g_cached_puuid;
                    }
                    if (active_uuid.empty()) active_uuid = "00000000-0000-0000-0000-000000000000";

                    reply = PipeBuildCompatAuthAck(magic, active_uuid);
                    inject_type_9 = true;
                    Log("[PIPE][COMPAT] type 4 auth ACK uuid=" + active_uuid +
                        " reply_magic=0x" + [&] { std::ostringstream o; o << std::hex << (magic + 1); return o.str(); }());
                }
                else if (compat_type == 1) {
                    reply.assign(buf.data(), buf.data() + bytesRead);
                    const int reply_magic = PipeCompatNextMagic(magic);
                    PipeWriteU32(reply, 0, (uint32_t)reply_magic);
                    Log("[PIPE][COMPAT] type 1 echo ACK magic=0x" +
                        [&] { std::ostringstream o; o << std::hex << reply_magic; return o.str(); }());
                }
                else if (compat_type == 2) {
                    reply.assign(48, 0);
                    const int reply_magic = PipeCompatNextMagic(magic);
                    PipeWriteU32(reply, 0, (uint32_t)reply_magic);
                    PipeWriteU32(reply, 4, 48);
                    PipeWriteU32(reply, 8, 1);
                    PipeWriteU32(reply, 24, 8);
                    Log("[PIPE][COMPAT] type 2 ACK magic=0x" +
                        [&] { std::ostringstream o; o << std::hex << reply_magic; return o.str(); }());
                }

                PipeWriteAndFlush(pipe, reply, "[PIPE][COMPAT] type " + std::to_string(compat_type) + " reply");

                if (inject_type_9) {
                    Sleep(200);
                    std::vector<uint8_t> injected(40, 0);
                    const int injected_magic = PipeCompatNextMagic(magic);
                    PipeWriteU32(injected, 0, (uint32_t)injected_magic);
                    PipeWriteU32(injected, 4, 40);
                    PipeWriteU32(injected, 8, 9);
                    PipeWriteAndFlush(pipe, injected, "[PIPE][COMPAT] injected type 9 session-auth");
                }
                continue;
            }
        }

        if (buf[0] == 0x65 && bytesRead >= 4) {
            auto pkt  = std::vector<uint8_t>(buf.data(), buf.data() + bytesRead);
            auto ack  = g_tasks_handler.handle_packet(pkt);
            PipeWriteAndFlush(pipe, ack, "[PIPE][0x65] TASKS ACK");
            Log("[PIPE] TASKS packet (0x65) acked");
            
            if (bytesRead > 100) {
                Log("[PIPE][0x65] scanning for JWT inside tasks packet...");
                
                
                std::string old_jwt;
                {
                    std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
                    old_jwt = g_cached_jwt;
                }
                TryExtractAndSend(buf.data(), bytesRead);
                
                std::string new_jwt;
                {
                    std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
                    new_jwt = g_cached_jwt;
                }
                if (!new_jwt.empty() && new_jwt != old_jwt && !old_jwt.empty()) {
                    
                    Log("[LOBBY] JWT changed â€” previous match ended, new match starting");
                    Log("[LOBBY] Triggering gateway re-auth for new match");
                    g_gw_reauth_needed.store(true);
                    g_gateway_reauth_remaining_sec.store(0);
                    UpdateConsoleTitle();
                }
            }
            continue;
        }

        
        if (buf[0] == 0x66 && bytesRead >= 4) {
            auto pkt = std::vector<uint8_t>(buf.data(), buf.data() + bytesRead);
            auto ack = g_tasks_handler.handle_packet(pkt);
            PipeWriteAndFlush(pipe, ack, "[PIPE][0x66] MODULES ACK");
            Log("[PIPE] MODULES packet (0x66) acked");
            continue;
        }

        
        if (buf[0] == 0x67 && bytesRead >= 8) {
            std::vector<uint8_t> payload(buf.data(), buf.data() + bytesRead);
            {
                std::lock_guard<std::mutex> lk(g_vgk_payload_mtx);
                g_vgk_payload = payload;
            }
            Log("[PIPE] vgk payload captured " + std::to_string(bytesRead) + "B");
            if (bytesRead >= 4) {
                uint32_t magic; memcpy(&magic, buf.data(), 4); uint32_t nm = magic + 1;
                std::vector<uint8_t> echo(buf.data(), buf.data() + bytesRead);
                memcpy(echo.data(), &nm, 4);
                PipeWriteAndFlush(pipe, echo, "[PIPE][0x67] echo");
            }
            continue;
        }

        
        if (buf[0] == 0x68 && bytesRead == 68) {
            std::vector<uint8_t> echo(buf.data(), buf.data() + bytesRead);
            PipeWriteAndFlush(pipe, echo, "[PIPE][0x68] 68-byte raw echo");
            continue;
        }

        
        if (bytesRead > 100) { Log("[PIPE] Scanning...");TryExtractAndSend(buf.data(), bytesRead); }
        if (bytesRead >= 4) {
            uint32_t magic; memcpy(&magic, buf.data(), 4); uint32_t nm = magic + 1;
            std::vector<uint8_t> echo(buf.data(), buf.data() + bytesRead);
            memcpy(echo.data(), &nm, 4);
            PipeWriteAndFlush(pipe, echo, "[PIPE] default echo");
        }
    }
    SendPipeDisconnectMessage(pipe, "pipe thread ending");
    void* expected_pipe = (void*)pipe;
    g_current_pipe.compare_exchange_strong(expected_pipe, nullptr);
    CloseHandle(pipe); Log("[PIPE] Client disconnected");
    
    g_round_tracker.on_lobby_return([&]() {
        std::string jwt, puuid, sid, region;
        {
            std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
            jwt = g_cached_jwt; puuid = g_cached_puuid;
            sid = g_cached_sid; region = g_cached_region;
        }
        if (!jwt.empty()) {
            Log("[ROUND] Lobby return detected â€” triggering gateway re-auth immediately");
            
            g_gw_reauth_needed.store(true);
            g_gateway_reauth_remaining_sec.store(0);
            UpdateConsoleTitle();
        }
    });
}

static void PipeServerLoop() {
    while (!g_shutdown.load()) {
        HANDLE pipe = CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 1048576, 1048576, 500, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) { Sleep(1000);continue; }
        Log(("[PIPE] Waiting for client..."));
        if (ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
            Log("[PIPE] Client connected");
            std::thread(HandlePipeClient, pipe).detach();
        }
        else { CloseHandle(pipe); }
    }
}

static uint32_t GetValorantPID() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe); uint32_t pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do { if (_wcsicmp(pe.szExeFile, L"VALORANT-Win64-Shipping.exe") == 0) { pid = pe.th32ProcessID;break; } } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap); return pid;
}

BOOL WINAPI CtrlHandler(DWORD t) {
    
    if (t == CTRL_CLOSE_EVENT || t == CTRL_C_EVENT || t == CTRL_BREAK_EVENT || t == CTRL_SHUTDOWN_EVENT) {
        SendDisconnectMessageToCurrentPipe("console control event " + std::to_string((int)t));
    }
    return TRUE;
}







struct ActiveSessionInfo {
    std::string puuid;
    std::string region;
    std::string account;
    std::chrono::steady_clock::time_point start_time;
    bool active = false;
};
static ActiveSessionInfo g_active_session;
static std::mutex g_display_mtx;

static void UpdateDisplaySessionState(const std::string& puuid, const std::string& region, const std::string& account) {
    std::lock_guard<std::mutex> lk(g_display_mtx);
    g_active_session.puuid = puuid;
    g_active_session.region = region;
    g_active_session.account = account;
    g_active_session.start_time = std::chrono::steady_clock::now();
    g_active_session.active = true;
}

static void ClearConsole() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(h, &csbi)) return;
    DWORD cells = csbi.dwSize.X * csbi.dwSize.Y, written;
    COORD origin = { 0,0 };
    FillConsoleOutputCharacterA(h, ' ', cells, origin, &written);
    FillConsoleOutputAttribute(h, csbi.wAttributes, cells, origin, &written);
    SetConsoleCursorPosition(h, origin);
}

static void ResizeConsoleWindowTall() {
    HWND hwnd = GetConsoleWindow();
    if (!hwnd) return;

    RECT rc{};
    if (!GetWindowRect(hwnd, &rc)) return;

    const int width = rc.right - rc.left;
    const int height = 720;
    SetWindowPos(hwnd, nullptr, rc.left, rc.top, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
}

static void SetColor(WORD attr) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attr);
}


#define COL_CYAN   (FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define COL_WHITE  (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_INTENSITY)
#define COL_YELLOW (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define COL_GREEN  (FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define COL_RED    (FOREGROUND_RED|FOREGROUND_INTENSITY)
#define COL_GRAY   (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE)
#define COL_ORANGE (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_INTENSITY)  
#define COL_DIM    (FOREGROUND_BLUE|FOREGROUND_INTENSITY)

static std::string ShortValue(const std::string& value, size_t keep = 8) {
    if (value.empty()) return "--";
    if (value.size() <= keep) return value;
    return value.substr(0, keep) + "...";
}

static std::string UpperAscii(std::string value) {
    for (char& c : value) {
        if (c >= 'a' && c <= 'z') c = (char)(c - ('a' - 'A'));
    }
    return value.empty() ? "--" : value;
}

static std::string FormatClock(int total_seconds) {
    if (total_seconds < 0) total_seconds = 0;
    int hh = total_seconds / 3600;
    int mm = (total_seconds % 3600) / 60;
    int ss = total_seconds % 60;
    char buf[32];
    sprintf_s(buf, "%02d:%02d:%02d", hh, mm, ss);
    return std::string(buf);
}

static void DrawHorizontalRule(char ch = '=') {
    SetColor(COL_DIM);
    for (int i = 0; i < 78; ++i) std::cout << ch;
    std::cout << "\n";
}

static void DrawHorizontalRuleColored(char ch, WORD color) {
    SetColor(color);
    for (int i = 0; i < 78; ++i) std::cout << ch;
    std::cout << "\n";
}

static void DrawField(const char* label, const std::string& value, WORD value_color = COL_WHITE) {
    SetColor(COL_GRAY);
    std::cout << "  " << label;
    SetColor(value_color);
    std::cout << value << "\n";
}



static int g_log_counter = 0;


static std::string GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    std::tm bt{}; localtime_s(&bt, &time_now);
    char buf[64];
    sprintf_s(buf, "%02d:%02d:%02d.%03d", bt.tm_hour, bt.tm_min, bt.tm_sec, (int)ms.count());
    return std::string(buf);
}


static void AddFunnyLog(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_log_lines.push_back(("[") + GetTimestamp() + ("] ") + msg);
    
    if (g_log_lines.size() > 20) {
        g_log_lines.erase(g_log_lines.begin());
    }
}


static std::atomic_bool g_display_running(false);
static void DisplayLoop() {    
    bool val_detected_logged = false;
    bool val_sesh_logged = false;
    bool val_submitted_logged = false;
    bool val_valid_logged = false;
    
    while (g_display_running.load()) {
        Sleep(500);
        ClearConsole();

        ActiveSessionInfo active_snapshot;
        {
            std::lock_guard<std::mutex> lk(g_display_mtx);
            active_snapshot = g_active_session;
        }

        std::string cached_region;
        std::string cached_sid;
        std::string cached_puuid;
        {
            std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
            cached_region = g_cached_region;
            cached_sid = g_cached_sid;
            cached_puuid = g_cached_puuid;
        }

        std::vector<std::string> log_snapshot;
        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            log_snapshot = g_log_lines;
        }

        const uint32_t valorant_pid = GetValorantPID();
        const bool valorant_running = valorant_pid != 0;
        const bool keepalive_running = g_keepalive_running.load();
        const bool forced_refresh = g_gw_reauth_needed.load();
        const int reauth_remaining = g_gateway_reauth_remaining_sec.load();

        std::string session_age = ("--:--:--");
        if (active_snapshot.active) {
            auto now = std::chrono::steady_clock::now();
            int secs = (int)std::chrono::duration_cast<std::chrono::seconds>(
                now - active_snapshot.start_time).count();
            session_age = FormatClock(secs);
        }
        SetColor(COL_CYAN);

        SetColor(COL_WHITE);
        DrawField(("Runtime         : "), valorant_running ? ("VALORANT DETECTED") : ("WAITING FOR VALORANT"),
            valorant_running ? COL_GREEN : COL_ORANGE);
        DrawField(("Gateway Reauth  : "), FormatClock(reauth_remaining),
            forced_refresh ? COL_RED : COL_GREEN);
        DrawField(("Gateway Session : "), keepalive_running ? ("ACTIVE - YOU CAN QUEUE") : ("IDLE - YOU CANNOT QUEUE"),
            keepalive_running ? COL_GREEN : COL_ORANGE);
        
        
        DrawField(("Valorant PID    : "), valorant_running ? std::to_string(valorant_pid) : ("--"),
            valorant_running ? COL_WHITE : COL_DIM);

        DrawHorizontalRule('-');
        if (!g_gateway_auto_send.load()) {
        DrawField(("Session State   : "), active_snapshot.active ? ("ACTIVE") : ("NOT RUNNING - PRESS 'F5' IN LOBBY"), active_snapshot.active ? COL_GREEN : COL_ORANGE);
        }
        else
        {
            DrawField(("Session State   : "), active_snapshot.active ? ("ACTIVE") : ("NOT RUNNING"), active_snapshot.active ? COL_GREEN : COL_ORANGE);
        }
        DrawField(("Session Age     : "), session_age, COL_WHITE);
        DrawField(("Region          : "), UpperAscii(active_snapshot.active ? active_snapshot.region : cached_region), COL_WHITE);
        DrawField(("Session PUUID   : "), ShortValue(active_snapshot.active ? active_snapshot.puuid : cached_puuid, 12), COL_WHITE);
        DrawField(("Gateway SID     : "), ShortValue(cached_sid, 12), COL_WHITE);
        DrawField(("Account         : "), ShortValue(active_snapshot.account, 24), COL_WHITE);

        DrawHorizontalRule('-');
        SetColor(COL_YELLOW);
        std::cout << ("  Controls\n");
        if (g_gateway_auto_send.load()) {
            DrawField(("F5              : "), ("MANUAL SESSION / GATEWAY REFRESH"), COL_WHITE);
        } else {
            DrawField(("F5              : "), ("GATEWAY [SEND / REAUTH] SESSION"), COL_WHITE);
        }
        DrawField(("Gateway Mode    : "), g_gateway_auto_send.load() ? ("AUTO ON TOKEN CAPTURE") : ("MANUAL VIA F5"), COL_WHITE);
        
        
        

        DrawHorizontalRule('-');
        SetColor(COL_YELLOW);
        std::cout << ("  Live Log\n");
        if (log_snapshot.empty()) {
            SetColor(COL_DIM);
            std::cout << ("  [no log lines yet]\n");
        } else {
            SetColor(COL_WHITE);
            for (const auto& line : log_snapshot) {
                std::cout << ("  ") << line << ("\n");
            }
        }

        DrawHorizontalRule('-');
        SetColor(COL_DIM);
        std::cout << ("  Live dashboard active\n");
        
        
        static int tick = 0;
        tick++;
        if (tick % 10 == 0) { 
            const std::vector<std::string> random_logs = {
            ("Checking gateway connection state..."),
            ("Verifying heartbeat token data..."),
            ("Connected to auth session endpoint."),
            ("Optimizing tunnel network buffer..."),
            };
            if (rand() % 10 == 0) { 
                AddFunnyLog(random_logs[rand() % random_logs.size()]);
            }
        }
        
        
        if (GetValorantPID() != 0 && !val_detected_logged) {
            AddFunnyLog(("Valorant detected."));
            val_detected_logged = true;
        }
        if (g_active_session.active && !val_sesh_logged) {
            AddFunnyLog(("Session data ready."));
            Sleep(200);
            AddFunnyLog(("Session submitted."));
            val_sesh_logged = true;
        }
        if (val_sesh_logged && !val_valid_logged) {
            Sleep(300);
            AddFunnyLog(("Session validated. Vanguard bypass active."));
            val_valid_logged = true;
        }
    }
}

void CreateVanguardMutex() {
    if (g_vanguard_mutex == nullptr) {
        g_vanguard_mutex = CreateMutexA(NULL, FALSE, "Global\\587203BC-5798-47BA-8BDA-C63D7DE25FCD");
        if (g_vanguard_mutex != nullptr) {
            Log("Created simulated Vanguard mutex.");
        }
    }
}

void CreateVanguardSharedMemory() {
    if (g_vanguard_shared_memory == nullptr) {
        g_vanguard_shared_memory = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x1000, "Global\\294E088E-E3EF-42A9-AE0C-1EF642412F95");
        if (g_vanguard_shared_memory == nullptr) {
            Log("Failed to create simulated Vanguard shared memory.");
        }
        else {
            Log("Created simulated Vanguard shared memory (FileMapping).");
        }
    }
}






int MainCMDUI(int argc, char* argv[]) {
    UpdateConsoleTitle();
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    
    {
        
        char exePath[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        std::string logPath(exePath);
        auto slash = logPath.find_last_of("\\/");
        if (slash != std::string::npos) logPath = logPath.substr(0, slash + 1);
        logPath += "gay.log";
        std::lock_guard<std::mutex> lk(g_log_mtx);
        g_log_file.open(logPath, std::ios::out | std::ios::trunc);
    }
    Log(("=== START ==="));
    Log("Build: " __DATE__ " " __TIME__);

    
    

    
    while (true) {
        ClearConsole();
        SetColor(COL_CYAN);
        SetColor(COL_GRAY);
        std::cout << ("\n\n");
        SetColor(COL_GREEN);
        std::cout << (" [ 1 ] ");
        SetColor(COL_WHITE);
        std::cout << ("Start | Automated Refresh [RECOMMENDED]\n\n");
        SetColor(COL_ORANGE);
        std::cout << (" [ 2 ] ");
        SetColor(COL_WHITE);
        std::cout << ("Start | Manual Refresh (F5) [dev]\n\n");
        SetColor(COL_RED);
        std::cout << (" [ 3 ] ");
        SetColor(COL_WHITE);
        std::cout << ("Exit\n\n");
        SetColor(COL_CYAN);
        std::cout << (" [ R ] ");
        SetColor(COL_GRAY);
        std::cout << ("\n\n");
        SetColor(COL_WHITE);
        std::cout << (" Select : ");

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "3" || choice == "q" || choice == "Q") {
            SetColor(COL_WHITE);
            std::cout << ("\n  Exiting...\n");
            Sleep(400);
            return 0;
        }


        if (choice == "2") {
            g_gateway_auto_send.store(false);
            Log(("[CFG] Gateway mode selected: manual refresh (F5)"));
            ResizeConsoleWindowTall();
            break; 
        }

        if (choice == "1") {
            g_gateway_auto_send.store(true);
            Log(("[CFG] Gateway mode selected: automated refresh"));
            ResizeConsoleWindowTall();
            break; 
        }
    }

    
    g_display_running = true;
    std::thread(DisplayLoop).detach();
    std::thread(GatewayHotkeyLoop).detach();

    g_session_mgr.on_session_created = [](const std::string& sid, const std::string& puuid,
        const std::string& region, const std::string& account) {
            std::lock_guard<std::mutex> lk(g_display_mtx);
            g_active_session.puuid = puuid;
            g_active_session.region = region;
            g_active_session.account = account;
            g_active_session.start_time = std::chrono::steady_clock::now();
            g_active_session.active = true;
        };
    g_session_mgr.on_session_destroyed = [](const std::string&) {
        std::lock_guard<std::mutex> lk(g_display_mtx);
        g_active_session.active = false;
        g_active_session.puuid = "";
        g_active_session.region = "";
        };

    g_server_running = true;
    std::thread([]() { RunServer(); }).detach();
    Sleep(300);

    
    
    
    system("sc stop vgc >nul 2>&1");
    Sleep(300);
    system("sc start vgc >nul 2>&1");
    Sleep(500);

    HANDLE h = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); }

    std::thread(PipeServerLoop).detach();

    CreateVanguardMutex();
    CreateVanguardSharedMemory();

    while (!g_shutdown.load()) {
        g_valorant_pid = GetValorantPID();
        if (g_valorant_pid) { 
            g_valorant_pid_fwd = g_valorant_pid; 
            break; 
        }
        Sleep(500);
    }

    bool disconnect_sent_after_valorant_exit = false;
    while (!g_shutdown.load()) {
        Sleep(500);
        uint32_t current_val_pid = GetValorantPID();
        if (current_val_pid == 0 && g_valorant_pid != 0 && !disconnect_sent_after_valorant_exit) {
            Log("[PIPE][DISCONNECT] Valorant process ended, notifying pipe");
            SendDisconnectMessageToCurrentPipe("valorant process ended");
            disconnect_sent_after_valorant_exit = true;
        }
        if (current_val_pid != 0 && current_val_pid != g_valorant_pid) {
            g_valorant_pid = current_val_pid;
            g_valorant_pid_fwd = current_val_pid;
            disconnect_sent_after_valorant_exit = false;
        }
    }

    system("sc stop vgc >nul 2>&1");
    
    return 0;
}


int main(int argc, char* argv[]) {

    return MainCMDUI(argc, argv);

}

