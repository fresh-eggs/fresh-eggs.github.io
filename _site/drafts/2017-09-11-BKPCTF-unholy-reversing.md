so, a shared library and a snippet of ruby code, lets get cracking.


By the look of it, the snippet of ruby is making use of a shared python object, lets crack that open with radare2.


with the help of ia and aaa, we see a very funny looking entry in the memory seciton:
vaddr=0x55f3302d7db7 paddr=0x00000db7 ordinal=002 sz=620 len=619 section=.rodata type=ascii string=exec """\nimport struct\ne=range\nI=len\nimport sys\nF=sys.exit\nX=[[%d,%d,%d],[%d,%d,%d],[%d,%d,%d]]\nY = [[383212,38297,8201833],[382494 ,348234985,3492834886],[3842947 ,984328,38423942839]]\nn=[5034563854941868,252734795015555591,55088063485350767967,-2770438152229037,142904135684288795,-33469734302639376803,-3633507310795117,195138776204250759,-34639402662163370450]\ny=[[0,0,0],[0,0,0],[0,0,0]]\nA=[0,0,0,0,0,0,0,0,0]\nfor i in e(I(X)):\n for j in e(I(Y[0])):\n  for k in e(I(Y)):\n   y[i][j]+=X[i][k]*Y[k][j]\nc=0\nfor r in y:\n for x in r:\n  if x!=n[c]:\n   print "dang..."\n   F(47)\n  c=c+1\nprint ":)"\n"""

this to me seems an awful lot like code siting plaing well in memory. Lets take a peek at anything that makes reference to this memory address.

interesting!!!!! 

So it looks as though the only refence to this is a function named method_check_key:
[0x55f3302d7a30]> axt 0x55f3302d7db7
data 0x55f3302d7c89 lea rcx, str.exec_____nimport_struct_ne_range_nI_len_nimport_sys_nF_sys.exit_nX____d__d__d____d__d__d____d__d__d___nY_____383212_38297_8201833___382494__348234985_3492834886___3842947__984328_38423942839___nn__5034563854941868_252734795015555591_55088063485350767967__2770438152229037_142904135684288795__33469734302639376803__3633507310795117_195138776204250759__34639402662163370450__ny___0_0_0___0_0_0___0_0_0___nA__0_0_0_0_0_0_0_0_0__nfor_i_in_e_I_X__:_n_for_j_in_e_I_Y_0___:_n__for_k_in_e_I_Y__:_n___y_i__j in sym.method_check_key




now that we have the lable for where this funciton is, lets analyse the hell out of it to see if we can deduce the key simply by observing the algorithm that checks it!


after about 45 minutes of debugging the following error message:
main.rb:1:in `require_relative': libruby-2.1.so.2.1: cannot open shared object file: No such file or directory - /home/x90/security/reversing/ctf/unholy/unholy.so (LoadError)
	from main.rb:1:in `<main>'

I finally came to the conclusion that it is not my ruby binary or any ctf tricks at play, simply that the shared lib was compiled with an older version of ruby.....


quick install of ruby version 2.1 on ubuntu:
sudo apt-get install python-software-properties
sudo apt-add-repository ppa:brightbox/ruby-ng
sudo apt-get update
sudo apt-get install ruby2.1



Now we can finally run it.



Alright, now to make the file executable so we can bring it up in radare2 for debugging

