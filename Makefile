# ChubaoFS Makefile
#

BIN_PATH := build/bin
BIN_SERVER := $(BIN_PATH)/cfs-server
BIN_CLIENT := $(BIN_PATH)/cfs-client
BIN_CLIENT2 := $(BIN_PATH)/cfs-client2
BIN_AUTHTOOL := $(BIN_PATH)/cfs-authtool

COMMON_SRC := build/build.sh Makefile
COMMON_SRC += $(wildcard storage/*.go util/*/*.go util/*.go repl/*.go raftstore/*.go proto/*.go)
SERVER_SRC := $(wildcard cmd/*.go authnode/*.go datanode/*.go master/*.go metanode/*.go)
CLIENT_SRC := $(wildcard client/*.go client/fs/*.go sdk/*.go)
CLIENT2_SRC := $(wildcard clientv2/*.go clientv2/fs/*.go sdk/*.go)
CLIENTTOOL_SRC := $(wildcard authtool/*.go)

RM := $(shell [[ -x /bin/rm ]] && echo "/bin/rm -rf" || echo "/usr/bin/rm -rf" )

default: all

phony := all
all: build

phony += build server authtool client client2
build: server authtool client

server: $(BIN_SERVER)

client: $(BIN_CLIENT)

client2: $(BIN_CLIENT2)
	
authtool: $(BIN_AUTHTOOL)

$(BIN_SERVER): $(COMMON_SRC) ${SERVER_SRC}
	@build/build.sh server

$(BIN_CLIENT): $(COMMON_SRC) $(CLIENT_SRC)
	@build/build.sh client

$(BIN_CLIENT2): $(COMMON_SRC) $(CLIENT2_SRC)
	@build/build.sh client2
	
$(BIN_AUTHTOOL): $(COMMON_SRC) $(CLIENTTOOL_SRC)
	@build/build.sh authtool

phony += clean
clean:
	@$(RM) build/bin

phony += dist_clean
dist-clean:
	@$(RM) build/bin
	@$(RM) build/out

phony += test
test:
	@build/build.sh test

.PHONY: $(phony)
