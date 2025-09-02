#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"  // Download from https://github.com/yhirose/cpp-httplib
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <ctime>      // For logging time stamps
#include <vector>
#include <algorithm>
#include <iomanip>
#include <cctype>
#include <clocale>    // For setlocale
#include <memory>     // For std::unique_ptr
#include <map>        // For MIME types
#include <cstdlib>

#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#else
#error "Missing the <filesystem> header."
#endif

// --- For checking port availability ---
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <iphlpapi.h>   
#include <cwctype>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#endif


// --- Version number ---
const std::string VERSION = "v2.1";

// --- Maximum allowed file upload size (1 GB) ---
const std::size_t MAX_UPLOAD_SIZE = 1024 * 1024 * 1024;

// ------------------------ Helpers ------------------------

std::string get_mime_type(const std::string& path) {
    auto pos = path.rfind('.');
    if (pos == std::string::npos) {
        return "application/octet-stream";
    }
    auto ext = path.substr(pos);
    static const std::map<std::string, std::string> mime_map = {
        {".html", "text/html"}, {".htm", "text/html"}, {".css", "text/css"},
        {".js", "application/javascript"}, {".mjs", "application/javascript"},
        {".json", "application/json"}, {".xml", "application/xml"},
        {".txt", "text/plain"}, {".csv", "text/csv"},
        {".jpg", "image/jpeg"}, {".jpeg", "image/jpeg"},
        {".png", "image/png"}, {".gif", "image/gif"},
        {".svg", "image/svg+xml"}, {".ico", "image/x-icon"},
        {".woff", "font/woff"}, {".woff2", "font/woff2"}, {".ttf", "font/ttf"},
        {".mp4", "video/mp4"}, {".webm", "video/webm"},
        {".mp3", "audio/mpeg"}, {".ogg", "audio/ogg"}, {".wav", "audio/wav"},
        {".pdf", "application/pdf"}, {".zip", "application/zip"}
    };
    auto it = mime_map.find(ext);
    if (it != mime_map.end()) return it->second;
    return "application/octet-stream";
}

// If the content type is "text-like", append charset for correct rendering
std::string add_charset_if_text(const std::string& mime) {
    if (mime.rfind("text/", 0) == 0 ||
        mime == "application/javascript" ||
        mime == "application/json" ||
        mime == "application/xml") {
        return mime + "; charset=utf-8";
    }
    return mime;
}

// Base64 encoding (for HTTP Basic Auth)
static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

std::string base64_encode(const std::string& in) {
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

// URL encode helper
std::string url_encode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (unsigned char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        }
        else {
            escaped << '%' << std::setw(2) << int(c);
        }
    }
    return escaped.str();
}



// Make first N bytes printable/safe for logs (CR/LF/TAB preserved, others as \xHH)
std::string sanitize_for_log(const std::string& s, size_t maxlen = 1024) {
    std::ostringstream o;
    o << std::uppercase << std::hex;
    size_t n = std::min(s.size(), maxlen);
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == '\r') { o << "\\r"; }
        else if (c == '\n') { o << "\\n"; }
        else if (c == '\t') { o << "\\t"; }
        else if (c >= 32 && c < 127) {
            o << static_cast<char>(c);
        }
        else {
            o << "\\x" << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
    }
    if (s.size() > maxlen) o << "…(truncated)";
    return o.str();
}

// POST logging
std::string build_post_preview(const httplib::Request& req, size_t maxlen = 1024) {

    if (!req.body.empty()) {
        return sanitize_for_log(req.body, maxlen);
    }

    if (!req.params.empty()) {
        std::string kvs;
        for (auto it = req.params.begin(); it != req.params.end(); ++it) {
            if (!kvs.empty()) kvs += "&";
            kvs += it->first + "=" + it->second;
            if (kvs.size() >= maxlen) break;
        }
        if (kvs.size() > maxlen) kvs.resize(maxlen);
        return sanitize_for_log(kvs, maxlen);
    }

    if (!req.files.empty()) {
        std::string out;
        for (const auto& kv : req.files) {
            const auto& name = kv.first;
            const auto& f = kv.second; // MultipartFormData

            if (f.filename.empty()) {
                // Treat as a normal form field: name=value
                std::string val = sanitize_for_log(f.content, maxlen);
                if (!out.empty()) out += "&";
                out += name + "=" + val;
            }
            else {
                // Real file upload: print safe metadata only
                std::string meta = name + ":[filename=" + f.filename
                    + ", type=" + f.content_type
                    + ", size=" + std::to_string(f.content.size()) + "]";
                if (!out.empty()) out += "; ";
                out += meta;
            }

            if (out.size() >= maxlen) break;
        }
        if (out.size() > maxlen) out.resize(maxlen);
        // Already sanitized field values above; metadata is ASCII.
        return out;
    }

    return {}; // nothing we can show
}


// ------------------------ Globals ------------------------

bool require_auth = false;
std::string g_expected_auth_header;
std::string g_web_root_path; // Path to the web root directory

// Helper: convert UTF-8 string to wide string on Windows
#ifdef _WIN32
std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstr[0], size_needed);
    return wstr;
}
#endif




// ANSI color support
inline bool supports_color() {
#ifdef _WIN32
    // Enable Virtual Terminal Processing (VT) if possible
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return false;

    DWORD mode = 0;
    if (!GetConsoleMode(hOut, &mode)) {
        // Not a console (redirected) OR very old console host -> no color
        return false;
    }

    DWORD newMode = mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    if (!SetConsoleMode(hOut, newMode)) {
        // Classic cmd.exe (without VT) will fail here -> no color
        return false;
    }
    return true;
#else
    // Respect NO_COLOR spec and avoid coloring when not a TTY or in "dumb" term
    if (std::getenv("NO_COLOR")) return false;
#include <unistd.h>
    if (!isatty(STDOUT_FILENO)) return false;
    const char* term = std::getenv("TERM");
    if (!term || std::string(term) == "dumb") return false;
    return true;
#endif
}

inline std::string colorize_blue(const std::string& s) {
    static const char* BLUE = "\x1b[34m";
    static const char* RESET = "\x1b[0m";
    return std::string(BLUE) + s + RESET;
}
inline std::string colorize_green(const std::string& s) {
    static const char* GREEN = "\x1b[32m";
    static const char* RESET = "\x1b[0m";
    return std::string(GREEN) + s + RESET;
}
inline std::string colorize_yellow(const std::string& s) {
    static const char* YELLOW = "\x1b[33m";
    static const char* RESET = "\x1b[0m";
    return std::string(YELLOW) + s + RESET;
}



//Logo
inline std::string make_startup_logo() {
    std::string ver = VERSION;
    if (!ver.empty() && (ver[0] == 'v' || ver[0] == 'V')) {
        ver.erase(0, 1);
    }

    std::ostringstream s;
    s <<
        R"(
 _____     _   _ _ _     _        
|  _  |___| |_| | | |___| |_
|     |  _|  _| | | | -_| . |
|__|__|_| |_| |_____|___|___| 
)";
    return s.str();
}


inline std::string make_startup_footer() {
    std::string ver = VERSION;                // e.g., "v2.1"
    if (!ver.empty() && (ver[0] == 'v' || ver[0] == 'V')) ver.erase(0, 1);

    std::ostringstream s;
    s << "ArtWeb by @art3x      ver " << ver << "\n"
        << "https://github.com/art3x\n\n";
    return s.str();
}

inline void print_logo() {
    std::string logo = make_startup_logo();
    std::string footer = make_startup_footer();

    if (supports_color()) {
        logo = colorize_green(logo);
        footer = colorize_blue(footer);
    }

#ifdef _WIN32
    std::wcout << utf8_to_wstring(logo);
    std::wcout << utf8_to_wstring(footer);
#else
    std::cout << logo << footer;
#endif
}


#ifdef _WIN32
inline std::wstring to_lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](wchar_t c) { return std::towlower(c); });
    return s;
}

inline bool starts_with_icase(const std::wstring& s, const std::wstring& pref) {
    if (s.size() < pref.size()) return false;
    auto sl = to_lower(s);
    auto pl = to_lower(pref);
    return std::equal(pl.begin(), pl.end(), sl.begin());
}

inline bool contains_icase(const std::wstring& s, const std::wstring& needle) {
    auto sl = to_lower(s);
    auto nl = to_lower(needle);
    return sl.find(nl) != std::wstring::npos;
}
#endif


inline void print_ipv4_list_after_logo() {
#ifdef _WIN32
    // Enumerate adapters (IPv4 only)
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG fam = AF_UNSPEC; // we'll filter per unicast addr
    ULONG sz = 0;
    if (GetAdaptersAddresses(fam, flags, nullptr, nullptr, &sz) != ERROR_BUFFER_OVERFLOW || sz == 0) {
        return;
    }
    std::vector<unsigned char> buf(sz);
    IP_ADAPTER_ADDRESSES* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(fam, flags, nullptr, addrs, &sz) != NO_ERROR) {
        return;
    }

    // Collect (name, ip) pairs, filtered by interface name
    std::vector<std::pair<std::wstring, std::wstring>> entries;

    for (auto* a = addrs; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;

        std::wstring name = a->FriendlyName ? a->FriendlyName : L"";
        if (name.empty()) continue;

        // Filter: Linux-like prefixes + common Windows equivalents
        bool match =
            starts_with_icase(name, L"eth") ||
            starts_with_icase(name, L"ens") ||
            starts_with_icase(name, L"tun") ||
            starts_with_icase(name, L"ethernet") ||
            starts_with_icase(name, L"vEthernet") ||
            contains_icase(name, L"Wi-Fi") ||            
            contains_icase(name, L"TAP") ||
            contains_icase(name, L"TUN") ||
            contains_icase(name, L"WireGuard") ||
            contains_icase(name, L"OpenVPN");

        if (!match) continue;

        for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            if (!ua->Address.lpSockaddr) continue;
            if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;

            auto* sin = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
            wchar_t ipw[64] = L"";
            if (InetNtopW(AF_INET, &sin->sin_addr, ipw, 64)) {
                entries.emplace_back(name, std::wstring(ipw));
            }
        }
    }

    std::sort(entries.begin(), entries.end());
    std::wostringstream oss;
    if (!entries.empty()) {
        oss << L"Listening on:\n";
        for (auto& e : entries) {
            oss << L"  " << e.first << L": " << e.second << L"\n";
        }
    }
    else {
        oss << L"Listening on: can't find any\n";
    }

    std::wstring out = oss.str();

    // Optional: colorize blue if VT is enabled
    if (supports_color()) {
        std::wcout << L"\x1b[33m" << out << L"\x1b[0m";
    }
    else {
        std::wcout << out;
    }
   

#else
    // POSIX: use getifaddrs for eth*/ens*/tun*
    ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != 0 || !ifaddr) return;

    std::vector<std::pair<std::string, std::string>> entries;

    for (ifaddrs* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa || !ifa->ifa_name || !ifa->ifa_addr) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;

        std::string name = ifa->ifa_name;
        if (!(name.rfind("eth", 0) == 0 || name.rfind("ens", 0) == 0 || name.rfind("tun", 0) == 0)) {
            continue;
        }

        char buf[INET_ADDRSTRLEN] = { 0 };
        auto* sin = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) {
            entries.emplace_back(name, std::string(buf));
        }
    }
    freeifaddrs(ifaddr);

    std::sort(entries.begin(), entries.end());

    std::ostringstream oss;
    if (!entries.empty()) {
        oss << "Listening on:\n";
        for (auto& e : entries) {
            oss << "  " << e.first << ": " << e.second << "\n";
        }
    }
    else {
        oss << "Listening on: can't find any\n";
    }

    std::string out = oss.str();
    if (supports_color()) out = colorize_yellow(out);
    std::cout << out;
#endif
}



// Help/usage
void print_usage(const char* progname) {
#ifdef _WIN32
    std::wstring wprogname = utf8_to_wstring(std::string(progname));
    std::wcout << L"Usage: " << wprogname << L" [options]\n"
        << L"Options:\n"
        << L"  -h, --help               Print this help message\n"
        << L"  -p, --port PORT          Set the port (default: 80 for HTTP, 443 for HTTPS)\n"
        << L"  -i, --index DIR_PATH     Serve static files from a directory. `index.html` is the default page.\n"
        << L"  --pass PASSWORD          Enable HTTP Basic authentication (username is 'admin')\n"
        << L"  -s, --ssl                Enable HTTPS mode\n"
        << L"  -c, --cert CERT_PATH     Path to SSL certificate file (required for --ssl)\n"
        << L"  -k, --key KEY_PATH       Path to SSL private key file (required for --ssl)\n";
#else
    std::cout << "Usage: " << progname << " [options]\n"
        << "Options:\n"
        << "  -h, --help               Print this help message\n"
        << "  -p, --port PORT          Set the port (default: 80 for HTTP, 443 for HTTPS)\n"
        << "  -i, --index DIR_PATH     Serve static files from a directory. `index.html` is the default page.\n"
        << "  --pass PASSWORD          Enable HTTP Basic authentication (username is 'admin')\n"
        << "  -s, --ssl                Enable HTTPS mode\n"
        << "  -c, --cert CERT_PATH     Path to SSL certificate file (required for --ssl)\n"
        << "  -k, --key KEY_PATH       Path to SSL private key file (required for --ssl)\n";
#endif
}

// HTTP Basic Auth check
bool authenticate(const httplib::Request& req, httplib::Response& res) {
    if (!require_auth) return true;
    auto auth = req.get_header_value("Authorization");
    if (auth != g_expected_auth_header) {
        res.status = 401;
        res.set_header("WWW-Authenticate", "Basic realm=\"User Visible Realm\"");
        res.set_content("Unauthorized", "text/plain");
        return false;
    }
    return true;
}

// File Upload Handler
void upload_handler(const httplib::Request& req, httplib::Response& res) {
    if (!authenticate(req, res)) return;

    auto file = req.get_file_value("file");
    if (file.filename.empty()) {
        res.status = 400;
        res.set_content("No file uploaded", "text/plain");
        return;
    }
    if (file.content.size() > MAX_UPLOAD_SIZE) {
        res.status = 413;
        res.set_content("Uploaded file is too large", "text/plain");
        return;
    }
    std::string safeFilename = fs::path(file.filename).filename().string();
    if (safeFilename.empty()) {
        res.status = 400;
        res.set_content("Invalid file name", "text/plain");
        return;
    }



    const fs::path upload_root = fs::current_path();
    auto canonical_root = fs::weakly_canonical(upload_root);

    std::string targetDirStr = ".";
    if (req.has_param("dir")) {
        targetDirStr = req.get_param_value("dir");
    }

    fs::path requested_path = upload_root / fs::u8path(targetDirStr);
    auto canonical_target_dir = fs::weakly_canonical(requested_path);


    if (canonical_target_dir.string().rfind(canonical_root.string(), 0) != 0) {
        res.status = 403; 
        res.set_content("Forbidden: Invalid target directory.", "text/plain");
        return;
    }

    fs::path fullPath = canonical_target_dir / fs::u8path(safeFilename);

    // Check for file overwrite.
    if (fs::exists(fullPath)) {
        res.status = 409; // Conflict
        res.set_content("File with this name already exists", "text/plain");
        return;
    }

    std::ofstream ofs(fullPath, std::ios::binary);
    if (!ofs) {
        // Before creating the directory, ensure the parent path is still safe.
        // This is a defense-in-depth check.
        if (fullPath.parent_path().string().rfind(canonical_root.string(), 0) != 0) {
            res.status = 403;
            res.set_content("Forbidden: Cannot create directory in this location.", "text/plain");
            return;
        }
        // Attempt to create the directory if it doesn't exist.
        fs::create_directories(fullPath.parent_path());
        ofs.open(fullPath, std::ios::binary); // Try again
        if (!ofs) {
            res.status = 500;
            res.set_content("Failed to save file", "text/plain");
            return;
        }
    }

    ofs.write(file.content.data(), file.content.size());
    ofs.close();
    res.set_content("File uploaded successfully", "text/plain");
}

// Unified Browse/Download Handler (for non-root paths)
void browse_handler(const httplib::Request& req, httplib::Response& res) {
    if (!authenticate(req, res)) return;

    std::string dir = req.matches[1];
    if (dir.empty()) dir = ".";

    fs::path reqPath(dir);
    if (reqPath.is_absolute() || dir.find("..") != std::string::npos) {
        res.status = 400;
        res.set_content("Invalid path", "text/plain");
        return;
    }
    fs::path fs_path = fs::u8path(dir);
    if (!fs::exists(fs_path)) {
        res.status = 404;
        res.set_content("Not found", "text/plain");
        return;
    }
    if (fs::is_regular_file(fs_path)) {
        std::ifstream ifs(fs_path, std::ios::binary);
        if (!ifs) {
            res.status = 500;
            res.set_content("Error reading file", "text/plain");
            return;
        }
        std::ostringstream oss;
        oss << ifs.rdbuf();

        const auto mime = get_mime_type(fs_path.string());
        const auto content_type = add_charset_if_text(mime);

        res.status = 200;
        res.set_content(oss.str(), content_type.c_str());

        // Only force download for unknown/binary types
        const bool likely_binary =
            (mime == "application/octet-stream") ||
            (mime.rfind("application/", 0) == 0 &&
                mime != "application/json" &&
                mime != "application/javascript" &&
                mime != "application/xml" &&
                mime != "application/pdf");

        if (likely_binary) {
            res.set_header("Content-Disposition",
                "attachment; filename=\"" + fs_path.filename().u8string() + "\"");
        }
        return;
    }

    // --- HTML directory listing ---
    std::stringstream html;
    html << "<!DOCTYPE html>\n"
        << "<html lang='en'>\n"
        << "<head>\n"
        << "  <meta charset='UTF-8'>\n"
        << "  <meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
        << "  <title>ArtWeb</title>\n"
        << "  <style>\n"
        << "    body { font-family: Arial, sans-serif; background-color: #f0f0f0; margin: 0; padding: 0; }\n"
        << "    .container { max-width: 800px; margin: 50px auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }\n"
        << "    h1 { color: #333; }\n"
        << "    .logo { font-family: 'Courier New', Courier, monospace; white-space: pre; color: #007ACC; font-size: 16px; text-align: center; margin-bottom: 20px; }\n"
        << "    form { margin-bottom: 20px; }\n"
        << "    input[type='file'] { padding: 10px; border: 1px solid #ccc; border-radius: 4px; }\n"
        << "    input[type='submit'] { background-color: #007ACC; color: #fff; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }\n"
        << "    input[type='submit']:hover { background-color: #005F99; }\n"
        << "    ul { list-style: none; padding: 0; }\n"
        << "    ul li { margin-bottom: 8px; }\n"
        << "    ul li a { text-decoration: none; color: #007ACC; }\n"
        << "    ul li a:hover { text-decoration: underline; }\n"
        << "    #uploadProgress { display: none; width: 100%; margin-top: 10px; }\n"
        << "    #dropZone { border: 2px dashed #007ACC; padding: 20px; text-align: center; margin-bottom: 20px; }\n"
        << "    .footer { text-align: center; font-size: 0.8em; color: #777; margin-top: 30px; }\n"
        << "  </style>\n"
        << "</head>\n"
        << "<body>\n"
        << "  <div class='container'>\n"
        << "    <div class='logo'>\n"
        << " _____     _   _ _ _     _   <br/>"
        << "|  _  |___| |_| | | |___| |_ <br/>"
        << "|     |  _|  _| | | | -_| . |<br/>"
        << "|__|__|_| |_| |_____|___|___|<br/>"
        << "    </div>\n"
        << "    <h1>Upload File</h1>\n"
        << "    <form id='uploadForm' method='POST' action='/upload?dir=" << url_encode(dir) << "' enctype='multipart/form-data'>\n"
        << "      <input type='file' name='file'/>\n"
        << "      <input type='submit' value='Upload'/>\n"
        << "      <progress id='uploadProgress' value='0' max='100'></progress>\n"
        << "    </form>\n"
        << "    <div id='dropZone'>Drag & drop files here to upload</div>\n"
        << "    <h1>Files in " << ((dir == ".") ? "/" : ("/" + dir)) << "</h1>\n"
        << "    <ul>\n";

    if (dir != ".") {
        fs::path currentPath = fs::u8path(dir);
        fs::path parent = currentPath.parent_path();
        std::string parent_str = parent.empty() ? "." : parent.u8string();
        std::string parent_link = (parent_str == ".") ? "/" : ("/" + parent_str);
        html << "      <li><a href='" << parent_link << u8"'>.. [↩ parent] </a></li>\n";
    }

    std::vector<std::pair<std::string, fs::path>> directories, files;
    for (const auto& entry : fs::directory_iterator(fs_path)) {
        std::string name = entry.path().filename().u8string();
        if (fs::is_directory(entry.path())) directories.push_back({ name, entry.path() });
        else if (fs::is_regular_file(entry.path())) files.push_back({ name, entry.path() });
    }
    std::sort(directories.begin(), directories.end(), [](auto const& a, auto const& b) { return a.first < b.first; });
    std::sort(files.begin(), files.end(), [](auto const& a, auto const& b) { return a.first < b.first; });
    for (const auto& p : directories) html << u8"      <li>📁 <a href='/" << ((dir == ".") ? "" : dir + "/") << p.first << "'>" << p.first << "/</a></li>\n";
    for (const auto& p : files) html << u8"      <li>🗎 <a href='/" << ((dir == ".") ? "" : dir + "/") << p.first << "'>" << p.first << "</a></li>\n";
    html << "    </ul>\n"
        << "    <div class='footer'>Version " << VERSION << "</div>\n"
        << "  </div>\n"
        << "  <script>\n"
        << "    document.getElementById('uploadForm').addEventListener('submit', function(event) {\n"
        << "      event.preventDefault();\n"
        << "      var fileInput = document.querySelector('input[type=\"file\"]');\n"
        << "      if (!fileInput.files.length) { alert('Please select a file.'); return; }\n"
        << "      var formData = new FormData(); formData.append('file', fileInput.files[0]);\n"
        << "      var xhr = new XMLHttpRequest(); xhr.open('POST', document.getElementById('uploadForm').action, true);\n"
        << "      xhr.upload.addEventListener('progress', function(e) {\n"
        << "        if (e.lengthComputable) {\n"
        << "          var percentComplete = Math.round((e.loaded / e.total) * 100);\n"
        << "          document.getElementById('uploadProgress').value = percentComplete;\n"
        << "        }\n"
        << "      });\n"
        << "      xhr.onloadstart = function() { document.getElementById('uploadProgress').style.display = 'block'; };\n"
        << "      xhr.onloadend = function() {\n"
        << "        document.getElementById('uploadProgress').style.display = 'none';\n"
        << "        if (xhr.status === 200) { alert('Upload complete!'); window.location.reload(); }\n"
        << "        else { alert('Upload failed.'); }\n"
        << "      };\n"
        << "      xhr.send(formData);\n"
        << "    });\n"
        << "    var dropZone = document.getElementById('dropZone');\n"
        << "    dropZone.addEventListener('dragover', function(e) { e.preventDefault(); dropZone.style.backgroundColor = '#e0e0e0'; });\n"
        << "    dropZone.addEventListener('dragleave', function(e) { e.preventDefault(); dropZone.style.backgroundColor = ''; });\n"
        << "    dropZone.addEventListener('drop', function(e) {\n"
        << "      e.preventDefault(); dropZone.style.backgroundColor = '';\n"
        << "      var files = e.dataTransfer.files; if (files.length === 0) return;\n"
        << "      var formData = new FormData(); formData.append('file', files[0]);\n"
        << "      var xhr = new XMLHttpRequest(); xhr.open('POST', document.getElementById('uploadForm').action, true);\n"
        << "      xhr.upload.addEventListener('progress', function(e) {\n"
        << "        if (e.lengthComputable) {\n"
        << "          var percentComplete = Math.round((e.loaded / e.total) * 100);\n"
        << "          document.getElementById('uploadProgress').value = percentComplete;\n"
        << "        }\n"
        << "      });\n"
        << "      xhr.onloadstart = function() { document.getElementById('uploadProgress').style.display = 'block'; };\n"
        << "      xhr.onloadend = function() {\n"
        << "        document.getElementById('uploadProgress').style.display = 'none';\n"
        << "        if (xhr.status === 200) { alert('Upload complete!'); window.location.reload(); }\n"
        << "        else { alert('Upload failed.'); }\n"
        << "      };\n"
        << "      xhr.send(formData);\n"
        << "    });\n"
        << "  </script>\n"
        << "</body>\n"
        << "</html>";
    res.set_content(html.str(), "text/html; charset=utf-8");
}

// Check if a port is free by attempting to bind
bool is_port_free(int port) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;
#endif
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    int result = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
#ifdef _WIN32
    closesocket(sockfd);
    WSACleanup();
#else
    close(sockfd);
#endif
    return (result == 0);
}

// Static Content Server Handler
void serve_static_content_handler(const httplib::Request& req, httplib::Response& res) {
    if (!authenticate(req, res)) return;

    auto relative_path_str = req.matches[1].str();
    if (relative_path_str.empty() || relative_path_str.back() == '/') {
        relative_path_str += "index.html";
    }
    fs::path requested_path = relative_path_str;
    fs::path full_path = fs::path(g_web_root_path) / requested_path;

    auto canonical_root = fs::weakly_canonical(g_web_root_path);
    auto canonical_full = fs::weakly_canonical(full_path);
    if (canonical_full.string().rfind(canonical_root.string(), 0) != 0) {
        res.status = 403;
        res.set_content("Forbidden: Access denied.", "text/plain");
        return;
    }
    if (!fs::exists(full_path) || !fs::is_regular_file(full_path)) {
        res.status = 404;
        res.set_content("Not Found", "text/plain");
        return;
    }
    std::ifstream ifs(full_path, std::ios::binary);
    if (!ifs) {
        res.status = 500;
        res.set_content("Internal Server Error: Could not read file.", "text/plain");
        return;
    }
    std::ostringstream oss;
    oss << ifs.rdbuf();
    res.status = 200;
    const auto mime = get_mime_type(full_path.string());
    res.set_content(oss.str(), add_charset_if_text(mime).c_str());
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);
#endif
    std::setlocale(LC_ALL, "");


    int port = 80;
    bool port_is_default = true;
    std::string auth_password = "";
    bool use_ssl = false;
    std::string cert_path, key_path;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") { print_usage(argv[0]); return 0; }
        else if ((arg == "-p" || arg == "--port") && i + 1 < argc) { try { port = std::stoi(argv[++i]); port_is_default = false; } catch (...) { std::cerr << "Invalid port value.\n"; return 1; } }
        else if (arg == "--pass" && i + 1 < argc) { auth_password = argv[++i]; require_auth = true; }
        else if (arg == "-s" || arg == "--ssl") { use_ssl = true; }
        else if ((arg == "-c" || arg == "--cert") && i + 1 < argc) { cert_path = argv[++i]; }
        else if ((arg == "-k" || arg == "--key") && i + 1 < argc) { key_path = argv[++i]; }
        else if ((arg == "-i" || arg == "--index") && i + 1 < argc) { g_web_root_path = argv[++i]; }
    }

    print_logo();
    print_ipv4_list_after_logo();

    if (!g_web_root_path.empty()) {
        if (!fs::exists(g_web_root_path)) {
#ifdef _WIN32
            std::wcerr << L"Error: Web root directory not found: " << utf8_to_wstring(g_web_root_path) << std::endl;
#else
            std::cerr << "Error: Web root directory not found: " << g_web_root_path << std::endl;
#endif
            return 1;
        }
        if (!fs::is_directory(g_web_root_path)) {
#ifdef _WIN32
            std::wcerr << L"Error: Path provided to --index is not a directory: " << utf8_to_wstring(g_web_root_path) << std::endl;
#else
            std::cerr << "Error: Path provided to --index is not a directory: " << g_web_root_path << std::endl;
#endif
            return 1;
        }
    }

    if (use_ssl) {
        if (port_is_default) port = 443;
        if (cert_path.empty() || key_path.empty()) {
#ifdef _WIN32
            std::wcerr << L"Error: --cert and --key are required when using --ssl." << std::endl;
#else
            std::cerr << "Error: --cert and --key are required when using --ssl." << std::endl;
#endif
            print_usage(argv[0]); return 1;
        }
        if (!fs::exists(cert_path)) {
#ifdef _WIN32
            std::wcerr << L"Error: Certificate file not found: " << utf8_to_wstring(cert_path) << std::endl;
#else
            std::cerr << "Error: Certificate file not found: " << cert_path << std::endl;
#endif
            return 1;
        }
        if (!fs::exists(key_path)) {
#ifdef _WIN32
            std::wcerr << L"Error: Key file not found: " << utf8_to_wstring(key_path) << std::endl;
#else
            std::cerr << "Error: Key file not found: " << key_path << std::endl;
#endif
            return 1;
        }
    }

    if (!is_port_free(port)) {
#ifdef _WIN32
        std::wcerr << L"Error: Port " << port << L" is already in use." << std::endl;
#else
        std::cerr << "Error: Port " << port << " is already in use." << std::endl;
#endif
        return 1;
    }

    if (require_auth) {
        g_expected_auth_header = "Basic " + base64_encode("admin:" + auth_password);
    }

    std::unique_ptr<httplib::Server> svr;
    if (use_ssl) {
        svr = std::make_unique<httplib::SSLServer>(cert_path.c_str(), key_path.c_str());
    }
    else {
        svr = std::make_unique<httplib::Server>();
    }

    if (!svr) {
#ifdef _WIN32
        std::wcerr << L"Error: Could not instantiate server." << std::endl;
#else
        std::cerr << "Error: Could not instantiate server." << std::endl;
#endif
        return 1;
    }

    svr->set_payload_max_length(MAX_UPLOAD_SIZE);

    if (!g_web_root_path.empty()) {
        svr->Get(R"(/(.*))", serve_static_content_handler);
    }
    else {
        svr->Get(R"(/(.*))", browse_handler);
        svr->Post("/upload", upload_handler);
    }

    // Catch-all POST handler (MUST be registered after real POST routes)
    // Ensures body parsing & logging even for unknown POST endpoints (404).
    svr->Post(R"(/(.*))", [](const httplib::Request& req, httplib::Response& res) {
        // Respect authentication if enabled
        if (require_auth) {
            if (!authenticate(req, res)) return; // sends 401
        }
        res.status = 404;
        res.set_content("Not Found", "text/plain");
        });

#ifdef _WIN32
    svr->set_logger([](const httplib::Request& req, const httplib::Response& res) {
        std::time_t t = std::time(nullptr);
        std::tm tm;
        localtime_s(&tm, &t);
        wchar_t time_str[100];
        wcsftime(time_str, sizeof(time_str) / sizeof(wchar_t), L"[%d/%b/%Y %H:%M:%S]", &tm);
        std::wstring fullPath = utf8_to_wstring(req.path);
        if (!req.params.empty()) {
            std::string queryStr = "?";
            bool first = true;
            for (const auto& param : req.params) {
                if (!first) { queryStr += "&"; }
                queryStr += param.first + "=" + param.second;
                first = false;
            }
            fullPath += utf8_to_wstring(queryStr);
        }
        std::wstring logLine = utf8_to_wstring(req.remote_addr) + L" - - " +
            time_str + L" \"" +
            utf8_to_wstring(req.method) + L" " +
            fullPath + L" HTTP/1.1\" " +
            std::to_wstring(res.status) + L" -\n";
        std::wcout << logLine;

        if (req.method == "POST") {
            auto preview = build_post_preview(req, 1024);
            if (!preview.empty()) {
                std::wcout << L"POST body (first 1024 bytes): "
                    << utf8_to_wstring(preview) << L"\n";
            }
        }
        });
#else
    svr->set_logger([](const httplib::Request& req, const httplib::Response& res) {
        std::time_t t = std::time(nullptr);
        std::tm tm;
        localtime_r(&t, &tm);
        char time_str[100];
        std::strftime(time_str, sizeof(time_str), "[%d/%b/%Y:%H:%M:%S]", &tm);
        std::string fullPath = req.path;
        if (!req.params.empty()) {
            fullPath += "?";
            bool first = true;
            for (const auto& param : req.params) {
                if (!first) { fullPath += "&"; }
                fullPath += param.first + "=" + param.second;
                first = false;
            }
        }
        std::cout << req.remote_addr << " - - " << time_str << " \""
            << req.method << " " << fullPath << " HTTP/1.1\" "
            << res.status << " -\n";

        if (req.method == "POST") {
            auto preview = build_post_preview(req, 1024);
            if (!preview.empty()) {
                std::cout << "POST body (first 1024 bytes): "
                    << preview << "\n";
            }
        }
        });
#endif

#ifdef _WIN32
    std::wcout << L"Starting " << (use_ssl ? L"HTTPS" : L"HTTP")
        << L" server on port " << port << L"\n";
    if (!g_web_root_path.empty()) {
        std::wcout << L"Serving static files from web root: " << utf8_to_wstring(g_web_root_path) << L"\n";
    }
    else {
        std::wcout << L"Running in file browser/upload mode.\n";
    }
#else
    std::cout << "Starting " << (use_ssl ? "HTTPS" : "HTTP")
        << " server on port " << port << "\n";
    if (!g_web_root_path.empty()) {
        std::cout << "Serving static files from web root: " << g_web_root_path << "\n";
    }
    else {
        std::cout << "Running in file browser/upload mode.\n";
    }
#endif

    if (!svr->listen("0.0.0.0", port)) {
#ifdef _WIN32
        std::wcerr << L"Error: Failed to start " << (use_ssl ? L"HTTPS" : L"HTTP")
            << L" server on port " << port << L". It might be busy." << std::endl;
#else
        std::cerr << "Error: Failed to start " << (use_ssl ? "HTTPS" : "HTTP")
            << " server on port " << port << ". It might be busy." << std::endl;
#endif
        return 1;
    }

    return 0;
}
