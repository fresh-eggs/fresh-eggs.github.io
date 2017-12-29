This past weekend I had the pleasure of participating in BackdoorCTF 2017 with the OpenToAll CTF team. 

In order to manage a 10th overall finish, a few binary reversing challenges stood in the way. While it is true that there were 3 of us working on the reversing challenges, credit goes to Kileak for absolutely smashing through these things before I had a chance to open radare2.

None the less, here is a write up for the BABY-0x41414141 reversing challenge.

We are presented with a binary named new_32, and along with that an ip and port to connect to with netcat. The binary we are given is hosted at that address and port so it is clear that we need to develop an exploit locally and fire it off to the remote server.

Running new_32, we are met with a simple question and answer loop:
1.

With that, lets start extracting some information from the file, starting with the memory section: 
2.

Hmm, now that looks ultra interesting, wonder if there are references to this address anywhere in the binary:
3.

Bingo! 

Now that we have found the function we need to jump into, we need to get a handle on the execution flow in order to take it over, lets look at the imports to see if there is anything in use that could help us:


Seems that fgets and printf are being used, either of these have the potential to yield us control of execution, lets start with the call to fgets:
4. 


FGETS
5.
The call is responsible for collecting our name, we can see that the size of the buffer is 0xc8, and it stores our value on the stack.

Evaluating the buffer space allocated on the stack, compared to the 0xc8(200) bytes we can pass, we quickly come to find out that we won't be able to reach anything dangerous. NEXT! 


PRINTF
Upon examining the call to printf, we can see that there is attacker controlled input being passed to the format string, and 0xc8 of it to boot! 
6.

Crash course on format string vulnerabilities for anyone interested: 

In an attempt to take over the flow of execution, we could craft a format string that will overwrite entries on the stack to return into the flag function we found earlier.




Thats all folks, hope you learned something, until next time.
