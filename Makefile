
LD = gcc
CC = gcc

CFLAGS = -g -Wall -ansi -D_XOPEN_SOURCE=500
LDFLAGS = -Wall -ansi

MLIBDIR = lib
DESTDIR = 
BUILD = build
SRC = src
EXAMPLES = $(SRC)/examples

VERSION=0
RELEASE=$(VERSION).1.1

all: $(BUILD)/libelfhacks.so.$(RELEASE) $(BUILD)/elfhacks.h

examples: $(BUILD)/dlsymhook.so

static: $(BUILD)/libelfhacks.a

$(BUILD):
	mkdir $(BUILD)

$(BUILD)/libelfhacks.so.$(RELEASE): $(BUILD)/elfhacks.o
	$(LD) $(LDFLAGS) -Wl,-soname,libelfhacks.so.$(VERSION) -shared $(BUILD)/elfhacks.o -o $(BUILD)/libelfhacks.so.$(RELEASE)
	ln -sf libelfhacks.so.$(RELEASE) $(BUILD)/libelfhacks.so.$(VERSION)
	ln -sf libelfhacks.so.$(RELEASE) $(BUILD)/libelfhacks.so

$(BUILD)/libelfhacks.a: $(BUILD)/elfhacks.o
	ar crs $(BUILD)/libelfhacks.a $(BUILD)/elfhacks.o

$(BUILD)/elfhacks.o: $(BUILD) $(SRC)/elfhacks.c $(SRC)/elfhacks.h
	$(CC) $(CFLAGS) -fPIC -o $(BUILD)/elfhacks.o -c $(SRC)/elfhacks.c

$(BUILD)/elfhacks.h: $(BUILD) $(SRC)/elfhacks.h
	cp $(SRC)/elfhacks.h $(BUILD)/elfhacks.h

$(BUILD)/dlsymhook.so: $(BUILD) $(EXAMPLES)/dlsymhook.c $(BUILD)/libelfhacks.so.$(RELEASE)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname,dlsymhook.so -fPIC -shared -L$(BUILD) -I$(BUILD) -lelfhacks $(EXAMPLES)/dlsymhook.c -o dlsymhook.so

install: $(BUILD)/libelfhacks.so.$(RELEASE) $(BUILD)/elfhacks.h
	install -Dm 0755 $(BUILD)/libelfhacks.so.$(RELEASE) $(DESTDIR)/usr/$(MLIBDIR)/libelfhacks.so.$(RELEASE)
	ln -sf libelfhacks.so.$(RELEASE) $(DESTDIR)/usr/$(MLIBDIR)/libelfhacks.so.$(VERSION)
	ln -sf libelfhacks.so.$(RELEASE) $(DESTDIR)/usr/$(MLIBDIR)/libelfhacks.so
	install -Dm 0644 $(BUILD)/elfhacks.h $(DESTDIR)/usr/include/elfhacks.h

install-static: $(BUILD)/libelfhacks.a $(BUILD)/elfhacks.h
	install -Dm 0755 $(BUILD)/libelfhacks.a $(DESTDIR)/usr/$(MLIBDIR)/libelfhacks.a
	install -Dm 0644 $(BUILD)/elfhacks.h $(DESTDIR)/usr/include/elfhacks.h

install-examples: $(BUILD)/dlsymhook.so
	install -Dm 0755 $(BUILD)/dlsymhook.so $(DESTDIR)/usr/$(MLIBDIR)/dlsymhook.so

clean:
	rm -f $(BUILD)/elfhacks.o
	rm -f $(BUILD)/libelfhacks.so $(BUILD)/libelfhacks.so.$(VERSION) $(BUILD)/libelfhacks.so.$(RELEASE)
	rm -f $(BUILD)/libelfhacks.a $(BUILD)/elfhacks.h
	rm -f $(BUILD)/dlsymhook.so
