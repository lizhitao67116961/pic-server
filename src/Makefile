################################################################################
# image makefile manual
################################################################################

USER_OBJS :=

LIBS := -lGraphicsMagickWand -lmysql -ljpeg -lpng -lpthread -lm -lgomp -lGraphicsMagick -ltiff -lfreetype -lXext -lX11

ASM_SRCS := 
OBJS := 
PROGRAM := "image"

# Every subdirectory with source files must be described here
SUBDIRS := ./util  ./server ./mysql ./memcache ./imgzip

RM := rm -rf

# All of the sources participating in the build are defined here
-include util/util.mk
-include server/server.mk
-include mysql/mysql.mk
-include memcache/memcache.mk
-include imgzip/imgzip.mk

# All Target
all: image

# Tool invocations
image: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	gcc  -o $(PROGRAM) $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '
	
# Other Targets
clean:
	-$(RM) $(OBJS) $(PROGRAM)
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY: