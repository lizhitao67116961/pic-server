################################################################################
# makefile manual
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 

C_SRCS += \
util/des_help.c \
util/imgzip_conf.c \
util/log.c \
util/md5.c \
util/ngx_alloc.c \
util/ngx_array.c \
util/ngx_buf.c \
util/ngx_event_timer.c \
util/ngx_hash.c \
util/ngx_http_parse.c \
util/ngx_http_parse_time.c \
util/ngx_list.c \
util/ngx_palloc.c \
util/ngx_queue.c \
util/ngx_rbtree.c \
util/ngx_readv_chain.c \
util/ngx_recv.c \
util/ngx_send.c \
util/ngx_shmem.c \
util/ngx_shmtx.c \
util/ngx_string.c \
util/ngx_time.c \
util/ngx_times.c \
util/ngx_writev_chain.c 

OBJS += \
util/des_help.o \
util/imgzip_conf.o \
util/log.o \
util/md5.o \
util/ngx_alloc.o \
util/ngx_array.o \
util/ngx_buf.o \
util/ngx_event_timer.o \
util/ngx_hash.o \
util/ngx_http_parse.o \
util/ngx_http_parse_time.o \
util/ngx_list.o \
util/ngx_palloc.o \
util/ngx_queue.o \
util/ngx_rbtree.o \
util/ngx_readv_chain.o \
util/ngx_recv.o \
util/ngx_send.o \
util/ngx_shmem.o \
util/ngx_shmtx.o \
util/ngx_string.o \
util/ngx_time.o \
util/ngx_times.o \
util/ngx_writev_chain.o 



# Each subdirectory must supply rules for building sources it contributes
util/%.o: util/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
#	gcc -I/usr/local/include/GraphicsMagick/ -I/root/work/mysql-connector-c-6.0.2-linux-glibc2.3-x86-64bit/include/ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	gcc -I/usr/local/include/GraphicsMagick/ -I/root/work/mysql-connector-c-6.0.2-linux-glibc2.3-x86-64bit/include/ -O3 -Wall -c -fmessage-length=0 -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


