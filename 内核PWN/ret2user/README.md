# Items
[2018 core](./2018_core)
   
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
这里也就是在咱们获得这俩兄弟的地址后在用户程序定义的函数调用，所以咱们只需在ROP中添加这个函数地址使其调用然后通过SWAPGS等系统调用返回用户态即可
   
1. 通过读取 /tmp/kallsyms 获取 commit_creds 和 prepare_kernel_cred 的方法相同，同时根据这些偏移能确定 gadget 的地址。
2. leak canary 的方法也相同，通过控制全局变量 off 读出 canary。
3. 与 kernel rop 做法不同的是 rop 链的构造:
   > 1. kernel rop 通过 内核空间的 rop 链达到执行 commit_creds(prepare_kernel_cred(0)) 以提权目的，之后通过 swapgs; iretq 等返回到用户态，执行用户空间的 system("/bin/sh") 获取 shell
    > 2. ret2usr 做法中，直接返回到用户空间构造的commit_creds(prepare_kernel_cred(0)) （通过函数指针实现）来提权，虽然这两个函数位于内核空间，但此时我们是 ring 0 特权，因此可以正常运行。之后也是通过 swapgs; iretq 返回到用户态来执行用户空间的 system("/bin/sh")
    

从这两种做法的比较可以体会出之所以要 ret2usr，是因为一般情况下在用户空间构造特定目的的代码要比在内核空间简单得多。（但是据我现在了解最不怕的就是他了(狗头)）


