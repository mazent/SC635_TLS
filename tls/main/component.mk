#
# "main" pseudo-component makefile.
#
# (Uses default behaviour of compiling all source files in directory, adding 'include' to include path.)

COMPONENT_EXTRA_CLEAN := versione.h

app.o: versione.h

versione.h:
	$(COMPONENT_PATH)/versione.sh

#$(call compile_only_if,$(CONFIG_USA_MS),appv.o)
#$(call compile_only_if_not,$(CONFIG_USA_MS),app.o)

# CPPFLAGS += -DLWIP_NETIF_STATUS_CALLBACK=1

