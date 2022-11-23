# SROP
为了补之前想快进到堆而掠过高级栈溢出，这里陆陆续续会补回来
## 基本介绍
SROP(Sigreturn Oriented Programming) 于 2014 年被 Vrije Universiteit Amsterdam 的 Erik Bosman 提出，其相关研究Framing Signals — A Return to Portable Shellcode发表在安全顶级会议 Oakland 2014 上，被评选为当年的 Best Student Papers。
今天先多讲一句，这个漏洞的利用大多数是依靠在底层内核的系统调用相关方面的知识，所以在我们现在处于的用户态不需要讲解代码，所以图会多点。
在这个利用过程之中，sigreturn是一个系统调用，他也是今天的重要内容，也是攻击的核心，在类 unix 系统发生 signal 的时候会被间接地调用。
## signal机制
signal 机制是类 unix 系统中进程之间相互传递信息的一种方法。一般，我们也称其为软中断信号，或者软中断。比如说，进程之间可以通过系统调用 kill 来发送软中断信号。一般来说，信号机制常见的步骤如下图所示：
![](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/figure/ProcessOfSignalHandlering.png)
1. 内核向某个进程发送 signal 机制，该进程会被暂时挂起，进入内核态。
2. 内核会为该进程保存相应的上下文，主要是将所有寄存器压入栈中，以及压入 signal 信息，以及指向 sigreturn 的系统调用地址。此时栈的结构如下图所示，我们称 ucontext 以及 siginfo 这一段为 Signal Frame。需要注意的是，这一部分是在用户进程的地址空间的。之后会跳转到注册过的 signal handler 中处理相应的 signal。因此，当 signal handler 执行完之后，就会执行 sigreturn 代码。
  
这里我来提一嘴，那就是大伙在这里看到内核其实对于今天知识的讲解关系不大，我们需要了解的仅仅只是这个回复上下文的系统调用而已。
![](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/figure/signal2-stack.png)
对于 signal Frame 来说，会因为架构的不同而有所区别，这里给出分别给出 x86 以及 x64 的 sigcontext
+ x86
```
struct sigcontext
{
  unsigned short gs, __gsh;
  unsigned short fs, __fsh;
  unsigned short es, __esh;
  unsigned short ds, __dsh;
  unsigned long edi;
  unsigned long esi;
  unsigned long ebp;
  unsigned long esp;
  unsigned long ebx;
  unsigned long edx;
  unsigned long ecx;
  unsigned long eax;
  unsigned long trapno;
  unsigned long err;
  unsigned long eip;
  unsigned short cs, __csh;
  unsigned long eflags;
  unsigned long esp_at_signal;
  unsigned short ss, __ssh;
  struct _fpstate * fpstate;
  unsigned long oldmask;
  unsigned long cr2;
};
```
+ x64
  
```

struct _fpstate
{
  /* FPU environment matching the 64-bit FXSAVE layout.  */
  __uint16_t        cwd;
  __uint16_t        swd;
  __uint16_t        ftw;
  __uint16_t        fop;
  __uint64_t        rip;
  __uint64_t        rdp;
  __uint32_t        mxcsr;
  __uint32_t        mxcr_mask;
  struct _fpxreg    _st[8];
  struct _xmmreg    _xmm[16];
  __uint32_t        padding[24];
};

struct sigcontext
{
  __uint64_t r8;
  __uint64_t r9;
  __uint64_t r10;
  __uint64_t r11;
  __uint64_t r12;
  __uint64_t r13;
  __uint64_t r14;
  __uint64_t r15;
  __uint64_t rdi;
  __uint64_t rsi;
  __uint64_t rbp;
  __uint64_t rbx;
  __uint64_t rdx;
  __uint64_t rax;
  __uint64_t rcx;
  __uint64_t rsp;
  __uint64_t rip;
  __uint64_t eflags;
  unsigned short cs;
  unsigned short gs;
  unsigned short fs;
  unsigned short __pad0;
  __uint64_t err;
  __uint64_t trapno;
  __uint64_t oldmask;
  __uint64_t cr2;
  __extension__ union
    {
      struct _fpstate * fpstate;
      __uint64_t __fpstate_word;
    };
  __uint64_t __reserved1 [8];
};
```
最后，signal handler 返回后，内核为执行 sigreturn 系统调用，为该进程恢复之前保存的上下文，其中包括将所有压入的寄存器，重新 pop 回对应的寄存器，最后恢复进程的执行。其中，32 位的 sigreturn 的调用号为 77，64 位的系统调用号为 15（调用号记孰，这里就跟read的0，write的1一样）。
 
---
## 攻击原理
仔细回顾一下内核在 signal 信号处理的过程中的工作，我们可以发现，内核主要做的工作就是为进程保存上下文，并且恢复上下文。这个主要的变动都在 Signal Frame 中。但是需要注意的是：

+ Signal Frame 被保存在用户的地址空间中，所以用户是可以读写的。
+ 由于内核与信号处理程序无关 (kernel agnostic about signal handlers)，它并不会去记录这个 signal 对应的 Signal Frame，所以当执行 sigreturn 系统调用时，此时的 Signal Frame 并不一定是之前内核为用户进程保存的 Signal Frame。
  
        
  说到这里，其实，SROP 的基本利用原理也就出现了。
其大致思路也就是在栈上伪造寄存器信息然后进行sigreturn系统调用，其实还蛮直观的，对于这个如何构造而言，由于这里我们会将所有的用户态寄存器都进行保存压栈，所以咱们人力来构造难免会有疏漏的地方，而且着本身也是个机械化的没技术含量的活，所以我们就交给了自动化程序处理，在目前的pwntools中就存在这样一个工具，这个工具的简单用法我写到下面

```
read = SigreturnFrame()           #此方法为pwntools内置函数
read.rax = constants.SYS_read #read函数系统调用号
read.rdi = 0  #read函数一参
read.rsi = stack_addr  #read函数二参
read.rdx = 0x400  #read函数三参
read.rsp = stack_addr  #构造rsp寄存器值
read.rip = syscall_ret #使得rip指向syscall的位置，在部署好read函数之后能直接调用0

```

可以看出工具的使用还是十分直观的

---
## 例题
1. [360春秋杯SROP基础题](./2016-360春秋杯-srop)
