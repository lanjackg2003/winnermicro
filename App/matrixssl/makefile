#/**************************************************************************
# * Kevin 2014-02-24                                                       *
# **************************************************************************/

#---------------------------------------------------------------------------
# Constant Variable definition
#---------------------------------------------------------------------------
ROOT = ../..
include $(ROOT)/Tools/tool_chain.def
LIB_DIR =	$(ROOT)/lib/$(LIBDIR)

#---------------------------------------------------------------------------
# Target definition (User)
#---------------------------------------------------------------------------
GOAL  = $(LIB_DIR)/wmssl.$(LIBTYPE)

#---------------------------------------------------------------------------
# Source section (User)
#---------------------------------------------------------------------------
ASM_SRC			+= 
C_SRC				+= cipherSuite.c      
C_SRC				+= hsHash.c            
C_SRC				+= matrixssl.c     
C_SRC				+= matrixsslApi.c
C_SRC				+= prf.c             
C_SRC				+= psk.c             
C_SRC				+= sslDecode.c             
C_SRC				+= sslEncode.c       
C_SRC				+= sslv3.c            
C_SRC				+= tls.c
C_SRC				+= core/corelib.c
C_SRC				+= core/osdep.c
C_SRC				+= crypto/digest/hmac.c
C_SRC				+= crypto/digest/md2.c
C_SRC				+= crypto/digest/md4.c
C_SRC				+= crypto/digest/sha224.c
C_SRC				+= crypto/digest/sha384.c
C_SRC				+= crypto/digest/sha512.c
C_SRC				+= crypto/keyformat/asn1.c
C_SRC				+= crypto/keyformat/base64.c
C_SRC				+= crypto/keyformat/x509.c
C_SRC				+= crypto/math/pstm_mul_comba.c
C_SRC				+= crypto/prng/prng.c
C_SRC				+= crypto/prng/yarrow.c
C_SRC				+= crypto/pubkey/dh.c
C_SRC				+= crypto/pubkey/ecc.c
C_SRC				+= crypto/pubkey/pkcs.c
C_SRC				+= crypto/pubkey/pubkey.c
C_SRC				+= crypto/pubkey/rsa.c
C_SRC				+= crypto/symmetric/aesGCM.c
C_SRC				+= crypto/symmetric/des3.c
C_SRC				+= crypto/symmetric/idea.c
C_SRC				+= crypto/symmetric/rc2.c
C_SRC				+= crypto/symmetric/seed.c

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

all: $(GOAL)

$(GOAL): $(OBJ_FILES)
	@$(AR) $(ARFLAGS) $@ $(OBJ_FILES)
	@$(ECHO) "***" $(GOAL) "is built successfully! ***"
	@$(ECHO) "---------"
	@rm -f $(OBJ_FILES:.o=.d) $(OBJ_FILES)
	
.PHONY: clean
clean:
	@rm -f $(GOAL)
	@rm -f $(OBJ_FILES:.o=.d) $(OBJ_FILES)
	
