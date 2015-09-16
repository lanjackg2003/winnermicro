#/**************************************************************************
# * Kevin 2014-02-24                                                       *
# **************************************************************************/

#---------------------------------------------------------------------------
# Constant Variable definition
#---------------------------------------------------------------------------
ROOT = ../..
include $(ROOT)/Tools/tool_chain.def 
LIB_DIR =	$(ROOT)/lib/GNU
OUTPUT_PATH=.

#---------------------------------------------------------------------------
# Target definition (User)
#---------------------------------------------------------------------------
GOAL = WM2014_01

#---------------------------------------------------------------------------
# Source section (User)
#---------------------------------------------------------------------------
ASM_SRC		+= $(ROOT)/Src/Boot/start_gcc.s
C_SRC		+= $(ROOT)/Src/Boot/retarget_gcc.c
C_SRC		+= $(ROOT)/App/wm_main.c
C_SRC		+= $(ROOT)/App/main.c

#---------------------------------------------------------------------------
# Linker options
#---------------------------------------------------------------------------
LDFLAGS	   += -static
LDFLAGS    += -nostartfiles
LDFLAGS    += -Tlink_ram.ld
LDFLAGS    += -entry=Vectors
LDFLAGS    += -mthumb-interwork
LDFLAGS    += -mthumb
#---------------------------------------------------------------------------
# Link Library Section
#---------------------------------------------------------------------------
LIB_SRC+=$(LIB_DIR)/Boot.a
LIB_SRC+=$(LIB_DIR)/clock.a
LIB_SRC+=$(LIB_DIR)/cpu.a
LIB_SRC+=$(LIB_DIR)/oneshot.a
ifeq ($(COST_DOWN),1)
LIB_SRC+=$(LIB_DIR)/wlan_costdown.a
else
LIB_SRC+=$(LIB_DIR)/wlan.a
endif
LIB_SRC+=$(LIB_DIR)/wmcmd.a
LIB_SRC+=$(LIB_DIR)/wmdhcpserver.a
LIB_SRC+=$(LIB_DIR)/wmdma.a
LIB_SRC+=$(LIB_DIR)/wmdnsserver.a
LIB_SRC+=$(LIB_DIR)/wmefuse.a
LIB_SRC+=$(LIB_DIR)/wmflash.a
LIB_SRC+=$(LIB_DIR)/wmfwup.a
LIB_SRC+=$(LIB_DIR)/wmgpio.a
LIB_SRC+=$(LIB_DIR)/wmhspi.a
LIB_SRC+=$(LIB_DIR)/wmhttpclient.a
LIB_SRC+=$(LIB_DIR)/wmirq.a
ifeq ($(COST_DOWN),1)
LIB_SRC+=$(LIB_DIR)/wmlitepoint_costdown.a
else
LIB_SRC+=$(LIB_DIR)/wmlitepoint.a
endif
LIB_SRC+=$(LIB_DIR)/wmlwip.a
LIB_SRC+=$(LIB_DIR)/wmmem.a
LIB_SRC+=$(LIB_DIR)/wmutils.a
LIB_SRC+=$(LIB_DIR)/wmnetapi.a
LIB_SRC+=$(LIB_DIR)/wmos.a
LIB_SRC+=$(LIB_DIR)/wmrtos.a
ifeq ($(COST_DOWN),1)
LIB_SRC+=$(LIB_DIR)/wmparams_costdown.a
else
LIB_SRC+=$(LIB_DIR)/wmparams.a
endif
LIB_SRC+=$(LIB_DIR)/wmspi.a
LIB_SRC+=$(LIB_DIR)/wmsys.a
LIB_SRC+=$(LIB_DIR)/wmtimer.a
LIB_SRC+=$(LIB_DIR)/wmuart.a
LIB_SRC+=$(LIB_DIR)/wmdemo.a
LIB_SRC+=$(LIB_DIR)/wmssl.a
LIB_SRC+=$(LIB_DIR)/wmntp.a
LIB_SRC+=$(LIB_DIR)/wmweb.a
#LIB_SRC+=$(LIB_DIR)/wmupnp.a
LIB_SRC+=$(LIB_DIR)/wmjson.a
LIB_SRC+=$(LIB_DIR)/wmexpat.a
LIB_SRC+=$(LIB_DIR)/wmsxml.a
#LIB_SRC+=$(LIB_DIR)/wmgmediarender.a
LIB_SRC+=$(LIB_DIR)/wmrtc.a
LIB_SRC+=$(LIB_DIR)/wmpwm.a

#---------------------------------------------------------------------------
# Implicit rules
#---------------------------------------------------------------------------
.c.o:
	@$(ECHO) "Compiling $<..."
	@$(CC) $(CCFLAGS) -c -o $*.o $< $(INCLUDE_DIR)

.s.o:
	@$(ECHO) "Compiling $<..."
	@$(ASM) $(ASMFLAGS) -c -o $*.o $< $(INCLUDE_DIR)

#---------------------------------------------------------------------------
# Explicit ruls
#---------------------------------------------------------------------------
OBJ_FILES	= $(C_SRC:%.c=%.o) $(ASM_SRC:%.s=%.o)

$(GOAL): $(GOAL).elf

$(GOAL).elf: $(OBJ_FILES) $(LIB_SRC)
	@$(CC) -o $(GOAL).elf $(OBJ_FILES) $(LDFLAGS) \
	-Wl,--gc-sections \
	-Wl,--start-group $(LIB_SRC) -lg -lgcc -Wl,--end-group \
	-Wl,-Map,$(OUTPUT_PATH)/$(GOAL).map -Wl,--warn-common
	$(ELF) --output-target=binary -S -g -x -X \
	-R .sbss -R .bss -R .reginfo -R .stack $(GOAL).elf $(GOAL).bin

	@$(ECHO) "*** $(GOAL) Binary image is built successfully! ***"
	./createimg.sh
	@rm -f $(OBJ_FILES:.o=.d) $(OBJ_FILES) $(GOAL).*
clean:
	@rm -f $(OBJ_FILES:.o=.d) $(OBJ_FILES) $(GOAL) $(OUTPUT_PATH)/$(GOAL).map \
	$(GOAL).elf $(GOAL).text $(OUTPUT_PATH)/$(GOAL).bin $(GOAL).nm *.bin *.hex
	
