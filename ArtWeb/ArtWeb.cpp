#include "httplib.h"  // Download from https://github.com/yhirose/cpp-httplib
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <ctime>      // For logging time stamps

#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#else
#error "Missing the <filesystem> header."
#endif

// --- Version number ---
const std::string VERSION = "v1.0";

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

// Global flag and expected header for authentication.
bool require_auth = false;
std::string g_expected_auth_header;

// --- Help/usage message ---
void print_usage(const char* progname) {
    std::cout << "Usage: " << progname << " [options]\n"
        << "Options:\n"
        << "  -h, --help          Print this help message\n"
        << "  --port PORT         Set the port (default: 80)\n"
        << "  --pass PASSWORD     Enable HTTP Basic authentication (username is always 'admin')\n"
        << "                      If not provided, no authentication is enforced.\n";
}

// --- HTTP Basic Auth check ---
// If authentication is enabled, the client must send a header matching g_expected_auth_header.
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

// --- Handlers ---

// Root endpoint: serves a stylish HTML page with a logo, an upload form with progress bar, a file list, and a version footer.
void root_handler(const httplib::Request& req, httplib::Response& res) {
    if (!authenticate(req, res))
        return;
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
        << "    <form id='uploadForm' method='POST' action='/upload' enctype='multipart/form-data'>\n"
        << "      <input type='file' name='file'/>\n"
        << "      <input type='submit' value='Upload'/>\n"
        << "      <progress id='uploadProgress' value='0' max='100'></progress>\n"
        << "    </form>\n"
        << "    <h1>Files in Current Directory</h1>\n"
        << "    <ul>\n";

    // List all regular files in the current directory.
    for (const auto& entry : fs::directory_iterator(".")) {
        if (fs::is_regular_file(entry.path())) {
            std::string filename = entry.path().filename().string();
            html << "      <li><a href='/" << filename << "'>" << filename << "</a></li>\n";
        }
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
        << "\n"
        << "      var xhr = new XMLHttpRequest();\n"
        << "      xhr.open('POST', '/upload', true);\n"
        << "\n"
        << "      xhr.upload.addEventListener('progress', function(e) {\n"
        << "        if (e.lengthComputable) {\n"
        << "          var percentComplete = Math.round((e.loaded / e.total) * 100);\n"
        << "          document.getElementById('uploadProgress').value = percentComplete;\n"
        << "        }\n"
        << "      });\n"
        << "\n"
        << "      xhr.onloadstart = function() {\n"
        << "        document.getElementById('uploadProgress').style.display = 'block';\n"
        << "      };\n"
        << "\n"
        << "      xhr.onloadend = function() {\n"
        << "        document.getElementById('uploadProgress').style.display = 'none';\n"
        << "        if (xhr.status === 200) {\n"
        << "          alert('Upload complete!');\n"
        << "          window.location.reload();\n"
        << "        } else {\n"
        << "          alert('Upload failed.');\n"
        << "        }\n"
        << "      };\n"
        << "\n"
        << "      xhr.send(formData);\n"
        << "    });\n"
        << "  </script>\n"
        << "</body>\n"
        << "</html>";

    res.set_content(html.str(), "text/html");
}

// File upload handler: saves the uploaded file to the current directory.
void upload_handler(const httplib::Request& req, httplib::Response& res) {
    if (!authenticate(req, res))
        return;
    auto file = req.get_file_value("file");
    if (file.filename.empty()) {
        res.status = 400;
        res.set_content("No file uploaded", "text/plain");
        return;
    }
    std::string file_path = file.filename;
    std::ofstream ofs(file_path, std::ios::binary);
    if (!ofs) {
        res.status = 500;
        res.set_content("Failed to save file", "text/plain");
        return;
    }
    ofs.write(file.content.data(), file.content.size());
    ofs.close();
    res.set_content("File uploaded successfully", "text/plain");
}

// File download handler: serves files from the current directory.
void download_handler(const httplib::Request& req, httplib::Response& res) {
    if (!authenticate(req, res))
        return;
    std::string filename = req.matches[1];
    // Basic check to prevent directory traversal.
    if (filename.find("..") != std::string::npos || filename.find('/') != std::string::npos) {
        res.status = 400;
        res.set_content("Invalid file name", "text/plain");
        return;
    }
    std::string file_path = filename;
    if (!fs::exists(file_path) || !fs::is_regular_file(file_path)) {
        res.status = 404;
        res.set_content("File not found", "text/plain");
        return;
    }
    std::ifstream ifs(file_path, std::ios::binary);
    if (!ifs) {
        res.status = 500;
        res.set_content("Error reading file", "text/plain");
        return;
    }
    std::ostringstream oss;
    oss << ifs.rdbuf();
    ifs.close();
    res.set_content(oss.str(), "application/octet-stream");
    res.set_header("Content-Disposition", "attachment; filename=\"" + filename + "\"");
}

int main(int argc, char* argv[]) {
    int port = 80;
    std::string auth_password = "";  // Default: no authentication

    // Parse command-line arguments.
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
        else if (arg == "--port" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        }
        else if (arg == "--pass" && i + 1 < argc) {
            auth_password = argv[++i];
            require_auth = true;
        }
    }

    // If authentication is enabled, compute the expected Basic Auth header.
    if (require_auth) {
        g_expected_auth_header = "Basic " + base64_encode("admin:" + auth_password);
    }

    httplib::Server svr;
    svr.Get("/", root_handler);
    svr.Post("/upload", upload_handler);
    svr.Get(R"(/(.+))", download_handler);

    // --- Logging: print each request
    svr.set_logger([](const httplib::Request& req, const httplib::Response& res) {
        std::time_t t = std::time(nullptr);
        std::tm tm;
#ifdef _WIN32
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif
        char time_str[100];
        std::strftime(time_str, sizeof(time_str), "[%d/%b/%Y %H:%M:%S]", &tm);
        std::cout << req.remote_addr << " - - " << time_str << " \""
            << req.method << " " << req.path << " HTTP/1.1\" "
            << res.status << " -\n";
        });

    std::cout << "Starting HTTP server on port " << port << std::endl;
    bool success = svr.listen("0.0.0.0", port);
    if (!success) {
        std::cerr << "Error: Failed to start HTTP server on port " << port << ". It might be busy." << std::endl;
        return 1;
    }

    return 0;
}
