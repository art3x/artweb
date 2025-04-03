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
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

// --- Version number ---
const std::string VERSION = "v1.1";

// --- Maximum allowed file upload size (1 GB) ---
const std::size_t MAX_UPLOAD_SIZE = 1024 * 1024 * 1024;

// --- Base64 encoding (for HTTP Basic Auth) ---
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
    if (valb > -6)
        out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}

// --- URL encode helper function (unused in logs) ---
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

// --- Helper: convert UTF-8 string to wide string on Windows ---
#ifdef _WIN32
std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty())
        return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstr[0], size_needed);
    return wstr;
}
#endif

// Global flag and expected header for authentication.
bool require_auth = false;
std::string g_expected_auth_header;

// --- Help/usage message ---
void print_usage(const char* progname) {
#ifdef _WIN32
    std::wstring wprogname = utf8_to_wstring(std::string(progname));
    std::wcout << L"Usage: " << wprogname << L" [options]\n"
        << L"Options:\n"
        << L"  -h, --help             Print this help message\n"
        << L"  --port PORT, -p PORT   Set the port (default: 80)\n"
        << L"  --pass PASSWORD        Enable HTTP Basic authentication (username is always 'admin')\n"
        << L"                         If not provided, no authentication is enforced.\n";
#else
    std::cout << "Usage: " << progname << " [options]\n"
        << "Options:\n"
        << "  -h, --help             Print this help message\n"
        << "  --port PORT, -p PORT   Set the port (default: 80)\n"
        << "  --pass PASSWORD        Enable HTTP Basic authentication (username is always 'admin')\n"
        << "                         If not provided, no authentication is enforced.\n";
#endif
}

// --- HTTP Basic Auth check ---
bool authenticate(const httplib::Request& req, httplib::Response& res) {
    if (!require_auth)
        return true;
    auto auth = req.get_header_value("Authorization");
    if (auth != g_expected_auth_header) {
        res.status = 401;
        res.set_header("WWW-Authenticate", "Basic realm=\"User Visible Realm\"");
        res.set_content("Unauthorized", "text/plain");
        return false;
    }
    return true;
}

// --- File Upload Handler ---
void upload_handler(const httplib::Request& req, httplib::Response& res) {
    if (!authenticate(req, res))
        return;

    auto file = req.get_file_value("file");
    if (file.filename.empty()) {
        res.status = 400;
        res.set_content("No file uploaded", "text/plain");
        return;
    }

    // Enforce maximum upload size.
    if (file.content.size() > MAX_UPLOAD_SIZE) {
        res.status = 413;  // Payload Too Large
        res.set_content("Uploaded file is too large", "text/plain");
        return;
    }

    // Sanitize the uploaded filename by extracting the base name.
    std::string safeFilename = fs::path(file.filename).filename().string();
    if (safeFilename.empty()) {
        res.status = 400;
        res.set_content("Invalid file name", "text/plain");
        return;
    }

    // Determine target directory from query parameter "dir" (default to ".")
    std::string targetDir = ".";
    if (req.has_param("dir")) {
        targetDir = req.get_param_value("dir");
        // Reject absolute paths and directory traversal.
        fs::path targetPath(targetDir);
        if (targetPath.is_absolute() || targetDir.find("..") != std::string::npos) {
            res.status = 400;
            res.set_content("Invalid target directory", "text/plain");
            return;
        }
    }

    // Build the full target file path.
    fs::path fullPath = fs::u8path(targetDir) / fs::u8path(safeFilename);
    std::ofstream ofs(fullPath, std::ios::binary);
    if (!ofs) {
        res.status = 500;
        res.set_content("Failed to save file", "text/plain");
        return;
    }
    ofs.write(file.content.data(), file.content.size());
    ofs.close();
    res.set_content("File uploaded successfully", "text/plain");
}

// --- Unified Browse Handler ---
void browse_handler(const httplib::Request& req, httplib::Response& res) {
    if (!authenticate(req, res))
        return;

    // The captured group (req.matches[1]) contains the requested path.
    // For "/" (empty match) use current directory.
    std::string dir = req.matches[1];
    if (dir.empty()) {
        dir = ".";
    }
    // Reject absolute paths and directory traversal attempts.
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

    // If the path is a file, serve it for download.
    if (fs::is_regular_file(fs_path)) {
        std::ifstream ifs(fs_path, std::ios::binary);
        if (!ifs) {
            res.status = 500;
            res.set_content("Error reading file", "text/plain");
            return;
        }
        std::ostringstream oss;
        oss << ifs.rdbuf();
        ifs.close();
        res.set_content(oss.str(), "application/octet-stream");
        res.set_header("Content-Disposition", "attachment; filename=\"" + fs_path.filename().u8string() + "\"");
        return;
    }

    // Build the HTML page (using your original layout).
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
        << "    <h1>Upload File</h1>\n";

    // Set the form action so that uploads go to the current directory.
    html << "    <form id='uploadForm' method='POST' action='/upload?dir=" << url_encode(dir)
        << "' enctype='multipart/form-data'>\n"
        << "      <input type='file' name='file'/>\n"
        << "      <input type='submit' value='Upload'/>\n"
        << "      <progress id='uploadProgress' value='0' max='100'></progress>\n"
        << "    </form>\n"
        << "    <div id='dropZone'>Drag & drop files here to upload</div>\n"
        << "    <h1>Files in " << ((dir == ".") ? "/" : ("/" + dir)) << "</h1>\n"
        << "    <ul>\n";

    // Add a parent directory link if not at the root.
    if (dir != ".") {
        fs::path currentPath = fs::u8path(dir);
        fs::path parent = currentPath.parent_path();
        std::string parent_str = parent.empty() ? "." : parent.u8string();
        std::string parent_link = (parent_str == ".") ? "/" : ("/" + parent_str);
        html << "      <li><a href='" << parent_link << u8"'>.. [↩ parent] </a></li>\n";
    }

    // Separate directories and files.
    std::vector<std::pair<std::string, fs::path>> directories;
    std::vector<std::pair<std::string, fs::path>> files;

    for (const auto& entry : fs::directory_iterator(fs_path)) {
        std::string name = entry.path().filename().u8string();
        if (fs::is_directory(entry.path()))
            directories.push_back({ name, entry.path() });
        else if (fs::is_regular_file(entry.path()))
            files.push_back({ name, entry.path() });
    }

    std::sort(directories.begin(), directories.end(), [](auto const& a, auto const& b) {
        return a.first < b.first;
        });
    std::sort(files.begin(), files.end(), [](auto const& a, auto const& b) {
        return a.first < b.first;
        });

    // List directories first.
    for (const auto& p : directories) {
        std::string name = p.first;
        std::string link = (dir == ".") ? name : (dir + "/" + name);
        html << u8"      <li>📁 <a href='/" << link << "'>" << name << "/</a></li>\n";
    }

    // Then list files.
    for (const auto& p : files) {
        std::string name = p.first;
        std::string link = (dir == ".") ? name : (dir + "/" + name);
        html << u8"      <li>🗎 <a href='/" << link << "'>" << name << "</a></li>\n";
    }

    html << "    </ul>\n"
        << "    <div class='footer'>Version " << VERSION << "</div>\n"
        << "  </div>\n"
        << "  <script>\n"
        << "    document.getElementById('uploadForm').addEventListener('submit', function(event) {\n"
        << "      event.preventDefault();\n"
        << "      var fileInput = document.querySelector('input[type=\"file\"]');\n"
        << "      if (!fileInput.files.length) {\n"
        << "        alert('Please select a file.');\n"
        << "        return;\n"
        << "      }\n"
        << "      var formData = new FormData();\n"
        << "      formData.append('file', fileInput.files[0]);\n"
        << "      var xhr = new XMLHttpRequest();\n"
        << "      xhr.open('POST', document.getElementById('uploadForm').action, true);\n"
        << "      xhr.upload.addEventListener('progress', function(e) {\n"
        << "        if (e.lengthComputable) {\n"
        << "          var percentComplete = Math.round((e.loaded / e.total) * 100);\n"
        << "          document.getElementById('uploadProgress').value = percentComplete;\n"
        << "        }\n"
        << "      });\n"
        << "      xhr.onloadstart = function() {\n"
        << "        document.getElementById('uploadProgress').style.display = 'block';\n"
        << "      };\n"
        << "      xhr.onloadend = function() {\n"
        << "        document.getElementById('uploadProgress').style.display = 'none';\n"
        << "        if (xhr.status === 200) {\n"
        << "          alert('Upload complete!');\n"
        << "          window.location.reload();\n"
        << "        } else {\n"
        << "          alert('Upload failed.');\n"
        << "        }\n"
        << "      };\n"
        << "      xhr.send(formData);\n"
        << "    });\n"
        << "    var dropZone = document.getElementById('dropZone');\n"
        << "    dropZone.addEventListener('dragover', function(e) {\n"
        << "      e.preventDefault();\n"
        << "      dropZone.style.backgroundColor = '#e0e0e0';\n"
        << "    });\n"
        << "    dropZone.addEventListener('dragleave', function(e) {\n"
        << "      e.preventDefault();\n"
        << "      dropZone.style.backgroundColor = '';\n"
        << "    });\n"
        << "    dropZone.addEventListener('drop', function(e) {\n"
        << "      e.preventDefault();\n"
        << "      dropZone.style.backgroundColor = '';\n"
        << "      var files = e.dataTransfer.files;\n"
        << "      if (files.length === 0) return;\n"
        << "      var formData = new FormData();\n"
        << "      formData.append('file', files[0]);\n"
        << "      var xhr = new XMLHttpRequest();\n"
        << "      xhr.open('POST', document.getElementById('uploadForm').action, true);\n"
        << "      xhr.upload.addEventListener('progress', function(e) {\n"
        << "        if (e.lengthComputable) {\n"
        << "          var percentComplete = Math.round((e.loaded / e.total) * 100);\n"
        << "          document.getElementById('uploadProgress').value = percentComplete;\n"
        << "        }\n"
        << "      });\n"
        << "      xhr.onloadstart = function() {\n"
        << "        document.getElementById('uploadProgress').style.display = 'block';\n"
        << "      };\n"
        << "      xhr.onloadend = function() {\n"
        << "        document.getElementById('uploadProgress').style.display = 'none';\n"
        << "        if (xhr.status === 200) {\n"
        << "          alert('Upload complete!');\n"
        << "          window.location.reload();\n"
        << "        } else {\n"
        << "          alert('Upload failed.');\n"
        << "        }\n"
        << "      };\n"
        << "      xhr.send(formData);\n"
        << "    });\n"
        << "  </script>\n"
        << "</body>\n"
        << "</html>";

    res.set_content(html.str(), "text/html");
}

// --- Check if a port is free by attempting to bind ---
bool is_port_free(int port) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
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

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Set the Windows console to use UTF-8 and wide-character output.
    SetConsoleOutputCP(CP_UTF8);
    _setmode(_fileno(stdout), _O_U16TEXT);
#endif
    // Set the global locale.
    std::setlocale(LC_ALL, "");

    int port = 80;
    std::string auth_password = "";  // Default: no authentication

    // Parse command-line arguments with basic error handling.
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
        else if ((arg == "--port" || arg == "-p") && i + 1 < argc) {
            try {
                port = std::stoi(argv[++i]);
            }
            catch (...) {
                std::cerr << "Invalid port value.\n";
                return 1;
            }
        }
        else if (arg == "--pass" && i + 1 < argc) {
            auth_password = argv[++i];
            require_auth = true;
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

    httplib::Server svr;
    // All GET requests (including "/") are handled by browse_handler.
    svr.Get(R"(/(.*))", browse_handler);
    svr.Post("/upload", upload_handler);

#ifdef _WIN32
    svr.set_logger([](const httplib::Request& req, const httplib::Response& res) {
        std::time_t t = std::time(nullptr);
        std::tm tm;
        localtime_s(&tm, &t);
        wchar_t time_str[100];
        wcsftime(time_str, sizeof(time_str) / sizeof(wchar_t), L"[%d/%b/%Y %H:%M:%S]", &tm);
        // Build full path including GET params if any using req.params.
        std::wstring fullPath = utf8_to_wstring(req.path);
        if (req.method == "GET" && !req.params.empty()) {
            std::string queryStr;
            bool first = true;
            for (const auto& param : req.params) {
                if (!first) {
                    queryStr += "&";
                }
                queryStr += param.first + "=" + param.second;
                first = false;
            }
            fullPath += L"?" + utf8_to_wstring(queryStr);
        }
        std::wstring logLine = utf8_to_wstring(req.remote_addr) + L" - - " +
            time_str + L" \"" +
            utf8_to_wstring(req.method) + L" " +
            fullPath + L" HTTP/1.1\" " +
            std::to_wstring(res.status) + L" -\n";
        std::wcout << logLine;
        if (req.method == "POST" && !req.body.empty() && req.body.size() < 1024) {
            std::wstring postData = utf8_to_wstring(req.body);
            std::wcout << L"POST data: " << postData << L"\n";
        }
        });
#else
    svr.set_logger([](const httplib::Request& req, const httplib::Response& res) {
        std::time_t t = std::time(nullptr);
        std::tm tm;
        localtime_r(&t, &tm);
        char time_str[100];
        std::strftime(time_str, sizeof(time_str), "[%d/%b/%Y %H:%M:%S]", &tm);
        // Build full path including GET params if any using req.params.
        std::string fullPath = req.path;
        if (req.method == "GET" && !req.params.empty()) {
            fullPath += "?";
            bool first = true;
            for (const auto& param : req.params) {
                if (!first) {
                    fullPath += "&";
                }
                fullPath += param.first + "=" + param.second;
                first = false;
            }
        }
        std::cout << req.remote_addr << " - - " << time_str << " \""
            << req.method << " " << fullPath << " HTTP/1.1\" "
            << res.status << " -\n";
        if (req.method == "POST" && !req.body.empty() && req.body.size() < 1024) {
            std::cout << "POST data: " << req.body << "\n";
        }
        });
#endif

#ifdef _WIN32
    std::wcout << L"Starting HTTP server on port " << port << L"\n";
#else
    std::cout << "Starting HTTP server on port " << port << "\n";
#endif

    if (!svr.listen("0.0.0.0", port)) {
#ifdef _WIN32
        std::wcerr << L"Error: Failed to start HTTP server on port " << port << L". It might be busy." << std::endl;
#else
        std::cerr << "Error: Failed to start HTTP server on port " << port << ". It might be busy." << std::endl;
#endif
        return 1;
    }

    return 0;
}
