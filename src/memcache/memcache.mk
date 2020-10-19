################################################################################
# makefile manual
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
memcache/ngx_http_memc_consistent_hash.c \
memcache/ngx_http_memc_handler.c \
memcache/ngx_http_memc_request.c \
memcache/ngx_http_memc_response.c 

OBJS += \
memcache/ngx_http_memc_consistent_hash.o \
memcache/ngx_http_memc_handler.o \
memcache/ngx_http_memc_request.o \
memcache/ngx_http_memc_response.o 


# Each subdirectory must supply rules for building sources it contributes
memcache/%.o: memcache/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
#	gcc -I/usr/local/include/GraphicsMagick/ -I/root/work/mysql-connector-c-6.0.2-linux-glibc2.3-x86-64bit/include/ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	gcc -I/usr/local/include/GraphicsMagick/ -I/root/work/mysql-connector-c-6.0.2-linux-glibc2.3-x86-64bit/include/ -O3 -Wall -c -fmessage-length=0 -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


