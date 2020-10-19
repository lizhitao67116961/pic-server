################################################################################
# makefile manual
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
imgzip/imgzip.c 

OBJS += \
imgzip/imgzip.o 


# Each subdirectory must supply rules for building sources it contributes
imgzip/%.o: imgzip/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
#	gcc -I/usr/local/include/GraphicsMagick/ -I/root/work/mysql-connector-c-6.0.2-linux-glibc2.3-x86-64bit/include/ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	gcc -I/usr/local/include/GraphicsMagick/ -I/root/work/mysql-connector-c-6.0.2-linux-glibc2.3-x86-64bit/include/ -O3 -Wall -c -fmessage-length=0 -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


