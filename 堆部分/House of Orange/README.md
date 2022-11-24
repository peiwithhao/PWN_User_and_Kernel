**这里开始著名的house of orange利用方式讲解**
## house of orange 介绍
House of Orange 与其他的 House of XX 利用方法不同，这种利用方法来自于 Hitcon CTF 2016 中的一道同名题目。由于这种利用方法在此前的 CTF 题目中没有出现过，因此之后出现的一系列衍生题目的利用方法我们称之为 House of Orange。
## 概述
House of Orange 的利用比较特殊，首先需要目标漏洞是堆上的漏洞但是特殊之处在于题目中不存在 free 函数或其他释放堆块的函数。我们知道一般想要利用堆漏洞，需要对堆块进行 malloc 和 free 操作，但是在 House of Orange 利用中无法使用 free 函数，因此 House of Orange 核心就是通过漏洞利用获得 free的效果。
## 原理
如我们前面所述，House of Orange 的核心在于在没有 free 函数的情况下得到一个释放的堆块 (unsorted bin)。 这种操作的原理简单来说是当前堆的 top chunk 尺寸不足以满足申请分配的大小的时候，原来的 top chunk 会被释放并被置入 unsorted bin 中，通过这一点可以在没有 free 函数情况下获取到 unsorted bins。

我们来看一下这个过程的详细情况，我们假设目前的 top chunk 已经不满足 malloc 的分配需求。 首先我们在程序中的malloc调用会执行到 libc.so 的_int_malloc函数中，在_int_malloc函数中，会依次检验 fastbin、small bins、unsorted bin、large bins 是否可以满足分配要求，因为尺寸问题这些都不符合。接下来_int_malloc函数会试图使用 top chunk，在这里 top chunk 也不能满足分配的要求，因此会执行如下分支
```
/*
Otherwise, relay to handle system-dependent cases
*/
else {
      void *p = sysmalloc(nb, av);
      if (p != NULL && __builtin_expect (perturb_byte, 0))
        alloc_perturb (p, bytes);
      return p;
}
```
此时 ptmalloc 已经不能满足用户申请堆内存的操作，需要执行 sysmalloc 来向系统申请更多的空间。 但是对于堆来说有 mmap 和 brk 两种分配方式，我们需要让堆以 brk 的形式拓展，之后原有的 top chunk 会被置于 unsorted bin 中。

综上，我们要实现 brk 拓展 top chunk，但是要实现这个目的需要绕过一些 libc 中的 check。 首先，malloc 的尺寸不能大于mmp_.mmap_threshold
```
if ((unsigned long)(nb) >= (unsigned long)(mp_.mmap_threshold) && (mp_.n_mmaps < mp_.n_mmaps_max))
```
如果所需分配的 chunk 大小大于 mmap 分配阈值，默认为 128K，并且当前进程使用 mmap() 分配的内存块小于设定的最大值，将使用 mmap() 系统调用直接向操作系统申请内存。
在 sysmalloc 函数中存在对 top chunk size 的 check，如下
```
assert((old_top == initial_top(av) && old_size == 0) ||
     ((unsigned long) (old_size) >= MINSIZE &&
      prev_inuse(old_top) &&
      ((unsigned long)old_end & pagemask) == 0));
```
这里检查了 top chunk 的合法性，如果第一次调用本函数，top chunk 可能没有初始化，所以可能 old_size 为 0。 如果 top chunk 已经初始化了，那么 top chunk 的大小必须大于等于 MINSIZE，因为 top chunk 中包含了 fencepost，所以 top chunk 的大小必须要大于 MINSIZE。其次 top chunk 必须标识前一个 chunk 处于 inuse 状态，并且 top chunk 的结束地址必定是页对齐的。此外 top chunk 除去 fencepost 的大小必定要小于所需 chunk 的大小，否则在_int_malloc() 函数中会使用 top chunk 分割出 chunk。
我们总结一下伪造的 top chunk size 的要求

1. 伪造的 size 必须要对齐到内存页
1. size 要大于 MINSIZE(64位下的0x10)
2. size 要小于之后申请的 chunk size + MINSIZE(0x10)
3. size 的 prev inuse 位必须为 1  
  
