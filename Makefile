CRYPTD := src/crypt
INC    := -Isrc/core -Isrc/pack -I$(CRYPTD)
BUILD  := build

# auto header deps: emit a .d per .o (-MMD), tolerate deleted headers (-MP)
DEPFLAGS := -MMD -MP

# make DEBUG=1 ...  -> extra debug build flags; defaults off
DEBUG    ?= 0
DBGFLAGS := $(if $(filter 1,$(DEBUG)),-DDEBUG -ggdb -g3)

CFLAGS := -fcf-protection=none -O0 -std=c17 -fno-jump-tables \
          -Wno-unused-function -Wall -Wextra -Werror $(DBGFLAGS)

HOSTFLAGS := -O0 -std=c17 -fcf-protection=none -fno-stack-protector \
             -falign-functions=256 -Wall -Wextra -Werror $(DBGFLAGS)

CORE_SRC  := src/core/elfstate.c
PACK_SRC  := src/pack/elfpack.c
CRYPT_SRC := $(filter-out $(CRYPTD)/main.c,$(wildcard $(CRYPTD)/*.c))

CORE_OBJ  := $(BUILD)/elfstate.o
PACK_OBJ  := $(BUILD)/elfpack.o
CRYPT_OBJ := $(patsubst $(CRYPTD)/%.c,$(BUILD)/cx_%.o,$(CRYPT_SRC))
OBJ       := $(PACK_OBJ) $(CORE_OBJ) $(CRYPT_OBJ)
DEP       := $(OBJ:.o=.d)

EXE       := famine

.PHONY: all clean fclean re
all: $(BUILD)/.sealed

$(BUILD)/.sealed: $(EXE)
	env FAMINE_SEAL=1 ./$(EXE)
	@touch $@

$(EXE): $(OBJ)
	gcc -o $@ $(OBJ)

$(CORE_OBJ): $(CORE_SRC) | $(BUILD)
	gcc $(CFLAGS) $(DEPFLAGS) $(INC) -c $< -o $@

$(BUILD)/cx_%.o: $(CRYPTD)/%.c | $(BUILD)
	gcc $(CFLAGS) $(DEPFLAGS) $(INC) -c $< -o $@

$(PACK_OBJ): $(PACK_SRC) | $(BUILD)
	gcc $(HOSTFLAGS) $(DEPFLAGS) $(INC) -c $< -o $@

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)

fclean: clean
	rm -rf $(EXE)

re: clean
	make -C . all

-include $(DEP)
