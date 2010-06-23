# This makefile builds OpenVPN-GUI using the mingw environment.

OPENSSL = /c/OpenSSL

RES_LANG = en
GUI_VERSION = 1.0.4

EXE = openvpn-gui-$(GUI_VERSION)-$(RES_LANG).exe

HEADERS = main.h \
	openvpn.h \
	openvpn_monitor_process.h \
	tray.h \
	viewlog.h \
	service.h \
	options.h \
	passphrase.h \
	openvpn-gui-res.h \
	proxy.h \
	ieproxy.h \
	registry.h \
	openvpn_config.h \
	chartable.h \
	scripts.h

OBJS = main.obj \
	tray.obj \
	openvpn.obj \
	openvpn_monitor_process.obj \
	viewlog.obj \
        service.obj \
	options.obj \
	passphrase.obj \
	proxy.obj \
	ieproxy.obj \
	registry.obj \
        openvpn_config.obj \
	scripts.obj \
	openvpn-gui-$(RES_LANG).res

INCLUDE_DIRS = -I. 
LIB_DIRS = /NODEFAULTLIB:libcmt /DEFAULTLIB:msvcrt /DEFAULTLIB:user32 /DEFAULTLIB:Advapi32 /DEFAULTLIB:WinInet /DEFAULTLIB:shell32

WARNS = -W -Wall -Wfloat-equal -Wundef -Wshadow -Wpointer-arith -Wbad-function-cast \
	-Wcast-align -Wwrite-strings -Wconversion -Wsign-compare \
	-Waggregate-return -Wmissing-noreturn -Wmissing-format-attribute \
	-Wredundant-decls -Winline -Wdisabled-optimization \
        -Wno-unused-function -Wno-unused-variable 

CFLAGS = -Zi -O2 -DDISABLE_CHANGE_PASSWORD -nologo
LDFLAGS = $(LIB_DIRS) /NOLOGO /INCREMENTAL /ALLOWISOLATION /MANIFESTUAC:"level=requireAdministrator uiAccess=false" /SUBSYSTEM:WINDOWS /DYNAMICBASE /NXCOMPAT /MACHINE:X86 /ERRORREPORT:QUEUE 

all : $(OBJS)
	$(CC) /Fe$(EXE) $(OBJS) /link $(LDFLAGS)

clean :
	del -f *.obj *.exe *.res