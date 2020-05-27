Some notes about the project and my intentions overall for the work I've done/am doing on the Wii.

# Why do any of this?

## Short answer

The Wii is simpler. It's got interesting features like an SD card, networking, later versions of IOS even support
an entire virtual machine for a scripting language that can run while the system is powered off via WiiConnect24.
Which has recieved very little (but now some!) documentation.

Additionally (K)ASLR, NX, KPP, etc. all don't really apply to the Wii. The Wii exploit chain is shorter, code exec
on PPC->Starlet execution in usermode->Starlet kernel execution. The PPC execution is fairly easy since games were
running bare metal and the Wii was before serious security was a concern in this way. Sure you might find a save
exploit on the Gamecube but the memory card is small and you can't do much interesting with it anyway. The assumption
that games are the only thing with access led to trusting data that shouldn't be trusted much more often.

This makes the Wii interesting (we can do something with an exploit), while not being hard to find an entry point
(webkit is pretty common to look aton acccount of complexity and JIT access for NX bypass, but it's also heavily
analyzed now too), or having to deal with messy ROP and multiple compromises after the exploit to do anything
useful.

## Long answer

Why is a very fair question. The Wii is more than 10 years old now. Hacking the Wii is more than 10 years old
now too. The Wii U came out and was hacked and there's a lot more info about that (and it's a lot more exciting
for the people that have one, given that it fixes the lack of OS, has more reasonable resources, etc). Fail0verflow
themselves (same people? I think? as hackmii) hacked it very quickly, but the interest and community for anything
beyond piracy never really appeared (they wanted people to port linux, a much better environment than some dinky
homebrewed specific set of libraries to replace the PPC kernel code). 

They released enough to pull off a hack on vWii to get the additional PPC cores, and tried to get people interested
in porting Linux, which made more sense for a platform with a "real" OS running on it anyway. Linux would have a
better starting point for drivers for the rest of the hardware which was more standard (Radeon GPU for example).
[https://fail0verflow.com/blog/2013/espresso/](https://fail0verflow.com/blog/2013/espresso/) there's the post on it.

Unfortunately nobody really cared to try. I think between the people that just wanted them to give away the keys and
the real exploit for Wii U mode (not just having a multi-core Wii to start), and the people who didn't see the point
of hacking a console just to run Linux on it when you can buy a cheap PC/Android console with enough performance to
do all the same stuff the Wii U could, there just wasn't interest.

I never had a Wii U, or even owned a later console (until the Switch), and while the Switch has some exciting factors
that make having the ability to run code on it interesting again, the fact is that I'm less interested in that than
just using it to play games. However the Wii still has some security, and the Starlet runs a full microkernel style
operating system with enough features to be interesting to look at, while having fewer of the complexities that make
modern operating systems less interesting to explore technically.

Furthermore I have a Wii and they're pretty cheap online, and getting a broken one for some hardware hacking would
be not an impossible or unreasonable expense to me even as a broke college student. Having a little project to
document an unknown memory map and unknown peripherals with very little documentation is an interesting task
without too many examples (if any), so I think it's worth attempting.

# Background on Starlet

This design was helpful (and not altogether terrible) for Nintendo because (generally? always?) DDR memory
needs to have it's timings loaded and voltages, etc, done before it can be used. Likewise at some point the
PLLs that clock the PPC/Memory/etc. need to be initialized with the right values and switched on. Power needs
to be set, and some chip needs to exist to manage the power button and other GPIOs that are used for the simpler
peripherals. (i.e. sensor bar output power, disc slot led, power led, etc.)

This is essentially what the bootrom on some CPUs can do, and what the early boot on others generally does. Having
some kind of built-in ram that doesn't need to be configured (or being able to use the cache in a special way like
x86 cpus typically seem to). This stuff is rarely documented since only the VERY VERY early boot code every cares
about it, and it's incredibly hardware (read vendor) specific, which often = proprietary and/or poorly documented.

I think chips with similar functions such as control of the power, buttons, leds, are also sometimes called system
controllers (syscon), or embedded controllers. On the 3DS (and PS vita?) these use RL78 processors from Renesas,
which seem to be a line of ultra-low power MCUs, ideal for something that is likely always on to respond to
the power button inputs.

Starlet is also a bit unique because it's both slightly more powerful than those power sipping RL78 chips, and
designed with custom silicon to support hardware AES and SHA, and assumed to be "secure" in that it implements
RSA in software but the PPC is assumed to be unable to influence it. It also is given specific control over the
rights of the PPC cpu when it comes to accessing some regions of memory (part of MEM2 is needed by Starlet) and
while some IO is (maybe?) blocked by hardware (PPC has a specific address bit masked off, MAYBE this is just
controlled by the AHBPROT register), most of the protections seem to be essentially peripherals that Starlet can
enable/disable to give the PPC more/less access for things like GC compatability requirements or factory/testing
convienience.

The INTENTIONAL interface with the PPC we know from the Wiki to be a set of "IPC" registers that can be controlled
by each side (although some can only be written by Starlet) which can trigger interrupts (which Starlet controls the
routing of since the interrupt controller can route to either device). I think a memory region would have worked
just as well, but the need for a trigger beyond polling is probably why there's hardware (which I suspect to just be
a latch connected to a specific address on the bus with the write signal routed to the IRQ controller).

blah blah. Probably more stuff but I don't feel like dumping any more info here.

# Background on the project 

Since I'm starting with boot1 (the "first stage" bootloader that runs after boot0 which is the mask rom boot),
this repo will probably be mostly focused on getting an understanding of how that works. Boot1 is slightly 
interesting because boot0 is so small that it's literally fully disassembled and most of the useful stuff
is entirely documented already (this is literally one of the earliest things on hackmii's blog).

Boot1 is much bigger in comparison, and should contain enough code to do some slightly more interesting 
things, but not a lot of documentation exists on it. Technically I think it's pretty well documented since
bushing released the IDC (IDA project info export I think) for his work on it up on hackmii, that same
article is where I got the binary (go find it yourself please hackmii is interesting enough to read even
10 years later). But I can't open an IDC easily the same way I can read a commented disassembly of boot0.
IOS and boot2 are even less documented, something I hope to remedy eventually as well.

Likewise boot2 is essentially a less interesting IOS, it's stripped off mostly everything that's not needed to
load IOS (and the system menu? IOS might do that too I think boot2 launches it somehow though). So boot2 is
both massive and contains stuff like the filesystem code and a lot of other junk, boot2 is also what bootmii
hooks into and therefore on vulnerable wiis (and I hear with illegally obtained binaries any wii could) anything
beyond boot2 can be fixed without hardware modifications (i.e. system menu bugs, filesystem corruption that doesn't
affect the blocks that store boot2, etc.). Boot2 is also the first layer that can be modified, boot0 being mask rom,
boot1 is verified by boot0 by checking it's hash against the otp fuses. The only cases it allows boot1 to start
is when the hash matches or the otp fuses are unprogrammed (factory). 

Boot1 contains enough code to do RSA so boot2 can be verified against a fixed public key that only Nintendo controls
(hash stored in otp I think? TODO: verify). Boot1 does it's setup, loads boot2 from the NAND, decrypts it, hashes it,
verifies the hash against the signature somewhere in the boot2 blob/flash, and verifies the rsa key somehow. This
means boot1 is the first interesting and complex code the Wii runs on a boot and nobody has really talked in depth
about it (probably because it's boring).

I started this because I actually want to figure out more (or just for myself) details about the Wii's main NAND
filesystem, which was somewhat confusing (mostly due to Ghidra's decompiler not cooperating with me) to work
out for myself. IOS sets up virtual memory and a lot of state that would likely make it far more challenging to work
out any unknown (or undiscovered by me) IO addresses and their functions.

My hope is to find a way to transfer the extensive understanding about the basics of IOS into knowledge about the
latest version of boot2 (much easier to get since it's just up on Nintendo's servers... for now...) and then be
able to use the smaller codebase of boot2 to help build knowledge about subsystem sof IOS again. That way eventually
I can find (and writeup!) my own exploit on a current version of IOS (since hackmii never published their exploits
since Nintendo never patched them).

Not just find an exploit but understand enough to make a useful (and non-destructive) patcher for IOS that can 
be used to hook IOS or PPC stuff in a useful way. (bushing made the point all that time ago that the Wii is unlike
other consoles because the games run bare-metal on the PPC leaving Nintendo with little to no ability if they even
wanted to for things like background tasks and new features). The ARM chip that IOS runs on is an ARM926EJS
based core fabricated by NEC. It is SLOW, especially compared to the PPC, and has just enough features to support
doing the IO processing and security it was likely designed for.

However simple things like screenshots could likely be done if some things are possible. First of all it seems like
it's been stated as a given that the chip can't interface with the GPU, but that seems really odd. First of all it's
literally part of the GPU package, and second of all it's got access to all of the memory (presumably on the same bus)
I find it very unlikely a second special path exists between Broadway (powerpc) and the GX (GPU) portion of Hollywood.
It's possible, since lots of non-important and non-trivial details weren't ever likely documented by anyone. But I
find it likely it's possible (if not directly then through hooking the PPC somehow). Which brings me to how I could
see this being possible:

1. Somehow halt the PPC without resetting it (or at least maintain enough state to resume it as it was)
2. Send commands directly to GX to set it up to draw into memory IOS controls or load PPC stub to do the same
3. Copy buffer of memory into area where PPC can see it, or just use Starlet to save it to NAND directly
4. Resume PPC

Finding a way to halt the PPC seems hard. Maybe there's a way though, if so it would also be an enourmously helpful
resource for a debugging tool.
