################################################################################
# makefile manual
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
server/ngx_channel.c \
server/ngx_connection.c \
server/ngx_cycle.c \
server/ngx_epoll_module.c \
server/ngx_event.c \
server/ngx_event_accept.c \
server/ngx_event_connect.c \
server/ngx_event_posted.c \
server/ngx_http.c \
server/ngx_http_header_filter_module.c \
server/ngx_http_image_entry.c \
server/ngx_http_image_module.c \
server/ngx_http_log_module.c \
server/ngx_http_request.c \
server/ngx_http_request_body.c \
server/ngx_http_special_response.c \
server/ngx_http_upstream.c \
server/ngx_http_upstream_round_robin.c \
server/ngx_http_write_filter_module.c \
server/ngx_output_chain.c \
server/ngx_process.c \
server/ngx_process_cycle.c \
server/ngx_socket.c \
server.c 

OBJS += \
server/ngx_channel.o \
server/ngx_connection.o \
server/ngx_cycle.o \
server/ngx_epoll_module.o \
server/ngx_event.o \
server/ngx_event_accept.o \
server/ngx_event_connect.o \
server/ngx_event_posted.o \
server/ngx_http.o \
server/ngx_http_header_filter_module.o \
server/ngx_http_image_entry.o \
server/ngx_http_image_module.o \
server/ngx_http_log_module.o \
server/ngx_http_request.o \
server/ngx_http_request_body.o \
server/ngx_http_special_response.o \
server/ngx_http_upstream.o \
server/ngx_http_upstream_round_robin.o \
server/ngx_http_write_filter_module.o \
server/ngx_output_chain.o \
server/ngx_process.o \
server/ngx_process_cycle.o \
server/ngx_socket.o \
server/server.o 



# Each subdirectory must supply rules for building sources it contributes
server/%.o: server/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	#gcc -I/usr/local/include/GraphicsMagick/ -I/root/work/mysql-connector-c-6.0.2-linux-glibc2.3-x86-64bit/include/ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	gcc -I/usr/local/include/GraphicsMagick/ -I/root/work/mysql-connector-c-6.0.2-linux-glibc2.3-x86-64bit/include/ -O3 -Wall -c -fmessage-length=0  -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


