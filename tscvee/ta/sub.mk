global-incdirs-y += include
global-incdirs-y += stc

srcs-y += tsc_vee_ta.c
srcs-y += src/uint256.c
srcs-y += src/sha3.c

# To remove a certain compiler flag, add a line like this
#cflags-tsc_vee_ta.c-y += -Wno-strict-prototypes
