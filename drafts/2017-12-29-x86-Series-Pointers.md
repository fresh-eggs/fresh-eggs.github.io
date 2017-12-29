This is the second installment of the x86 series where we cover the basics of assembly from a C programmers perspective.

Today we will focus on pointers, how to identify them in assembly and how to spot the different functions of a pointer.

First up, take a look at this simple example:

#include <stdio.h>


int main(){
	char our_char = 'Q';
	char *ptr_x = &our_char;

	printf("this is your ptr_x addr: 0x%x\n", &ptr_x);
	printf("this is your ptr_x value: 0x%x\n", ptr_x);
	printf("finally, here is the value it points to: %s\n", *ptr_x);
	return 0;
}


We can see that it makes allocates a char, passes it to a pointer, followed by printing the three different pieces that make up the pointer in question.


Now let's dive into some assembly! 


