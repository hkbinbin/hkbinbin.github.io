---
title: "Blind Pwn的一些思考"
description: 
date: 2025-04-28T22:06:57+08:00
categories:
    - CTF
tags:
    - Format String
    - BROP
    - userspace
comments: true
---

# Blind Pwn的一些思考

## 闲聊

2025年长城杯决赛渗透出现了一个pwn服务，然而并没有附件，经过测试发现是format string类型的漏洞，不禁想起Blind Pwn，但是打的又少，导致浪费了好几个小时…

期间对利用的一些思考，借此机会记录一下

## 问题的关键

问题的关键是无任何有效信息，即使栈溢出也不知道应该跳转到哪里

对此有两种思路

1. 爆破地址观察程序相应情况，来判断是否进入了某些函数（如输出函数，main函数等），这种对应的手法应该是BROP（利用条件为纯栈溢出，NO PIE）
2. 通过fmt漏洞直接leak elf数据（%s-%p等来确认），这种手法利用条件为format string漏洞

无论是哪种思路，第一大步的目的就是寻找到puts/printf/write这些函数，进一步泄露整个elf，当这一步完成的时候，就和普通pwn没有区别了

## BROP

这种手法需要大量尝试/爆破，利用条件为栈溢出/NO PIE，在没有PIE保护的情况下，我们可以知道程序的elf base，然后在挟持执行流的时候，将返回地址遍历挟持整个elf代码段的每个地址，寻找对应gadgets

### Stopping gadgets

Stopping gadgets指的是让程序卡住但不崩溃的gadget，比如main/_start，这几个函数的地址，它会让程序重启，但不会断开socket链接，通过这一现象就可以判断是否拿到Stopping gadgets。

Stopping gadgets会为下一步拿到其他gadgets作为一个依靠

### register gadgets

下一步寻找register gadgets，这一步不确定性挺大的

如需要寻找`pop rdi; ret` 这个gadget，将payload设置为

```python
flat([
	padding,
	pop_rdi, 0,
	Stopping gadget
])
```

这个payload会将设pop_rdi的地址满足它是一个`pop xxx ; ret` 结构，然后不能影响后面进入Stopping gadget

所以依赖这个Stopping gadget，我们可以根据程序如果挂了，那就这个地址不满足，否则应该是满足这个结构的

### leak functions

接下来下一步需要寻找能够输出的函数，比如`puts` /`printf` /`write` 这几个，这一步同样依赖于上面的register gadgets以及Stopping gadgets

构造payload如

`puts` /`printf`

```python
flat([
	padding,
	pop_rdi, xxx,
	puts_addr,
	Stopping gadget
])
```

这里的puts_addr需要遍历整个代码段，pop_rdi有多种情况，取决于得到满足的register gadgets数量，所以这一步需要爆破的更多

这里xxx填什么呢，我们都知道ELF程序有个header，里面的值是\x7fELF开头的

所以把xxx填为`0x400000` 即可

如果成功找到，那么就会输出\x7fELF

`write` 

```python
flat([
	padding,
	pop_rdi, 1,
	pop_rsi, xxx,
	pop_rdx, 0x50,
	puts_addr,
	Stopping gadget
])
```

使用write输出就会更加复杂，因为需要爆破的次数变成了puts_addr可能值 * register gadgets数量^3

理论可行，但实际上估计很难爆出来

### Leak ELF

当上面的三种gadgets全部找到之后，我们就能确定一整条leak链了，通过挟持执行流主动调用这条利用链就可以把整个ELF dump下来，后面就不是什么难事了

## Format String in Blind Pwn

这种情况下会相对于BROP更加简单(吗?)

fmt漏洞又分为栈上和堆上两种

对于栈上自然是好做的，直接就可以往栈里布置elf指针，然后通过`%s` 来泄露对应地址，虽然`\x00` 无法获知，但是我们可以通过无输出来判断

堆上其实也好做，区别在于需要先通过`%n` 链子来对指针进行修改，这里需要回忆一下堆上fmt pwn是怎么做的，最通用的做法就是利用栈上环境变量的指针，它的结构长这样：

`A: B→C("/home/hkbin/pwn")`

在A地址上，存在B指针，指向C，C的内容是环境变量

此时通过`%n` 系列的fmt，修改C的值，让它一步步成为一个栈地址

此时就变成这样的链子

`A: B->C->D(xxx)` 

后续即可配合`A: B->C` 以及`B: C->D` 这两条链子实现任意地址读写了

对于Blind Pwn同样也可以这样做，创造了自己的`B: C->D` 链子之后就可以去leak ELF了

但是缺点也很明显，构造`B: C->D` 链子的成本比较高，需要很长的payload，并且往往需要使用`%lln` ，1byte1byte地写入，速度比较慢，也比较复杂

## 回到闲聊

长城杯题目环境是栈上的fmt漏洞，那为啥很难打呢，因为他会`\x00` 截断

在这种情况下我们无法随意地插入例如`0x400000` 这样的地址，这会导致一些对齐后的函数没法完好地dump下来，并且输入长度也有限，想构造类似堆上fmt的链子也无法完成(

😭 😭