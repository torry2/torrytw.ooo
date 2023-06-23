---
title: "p4 CTF Finals - Scoundrelike (re)"
date: 2023-06-22T00:00:00+08:00
sort: ["all", "ctf", "featured", "writeup", "rev"]
draft: false
---
![image](/scoundrelike/scoundrelike.gif)

<aside id="toc">
    <h4>Table of Contents</h4>
	<h4><a href="#concept-&-analysis">1. </a>Concept & Analysis</h4>
	<h4><a href="#"calculate>3. </a>Calculate</h4>
	<h4><a href="#code-optimisation">4. </a>Code Optimisation</h4>
	<h4><a href="#pigeon-patch">5. </a>Pigeon Patch</h4>
	<h4><a href="#conclusion">5. </a>Conclusion</h4>
</aside>

# Concept & Analysis

> Easy RE challenge to get you going

Running the binary, we find a 2D ascii game (image above), navigating with <WASD> as the <@> symbol, we can navigate between the <#> walls and interact with a selection of letters. Interacting with the characters, each appear as a `p4 team` member that provides a series of diologue.

The interaction with C (`cypis`) along side the challenge description gives a decent idea of how to solve the challenge:
```
<cypis> Welcome traveler on your quest.
<cypis> Bring me five artifacts of great power and I'll reward you generously.
<cypis> The gate is now open. Go if you dare.
<cypis> ...
<cypis> Don't worry, the challenges are not particularly hard.
<cypis> Actually this is just a token RE task for C reversing enthusiasts.
<cypis> Also I get to generate some ASCII art.
<cypis> Anyway, go on and bring me the items.
```
We need to collect 5 artifacts and return to `cypis` in order to get the flag. We can assume is collected from 5 characters each as a small RE challenge. We can conduct some basic checks in order to begin reversing, however the decription and information gives us enough to start (throwing the binary at IDA).

Ignoring main, we can simply use strings to locate the `cypis` function, as well as each other character function simply by locating the corresponding name or diologue.

Here is the `cypis` function, which I have commented to describe the purpose of:
```c
int sub_34AA()
{
  sub_3414(); ; terminal colourisation
  sub_3427(off_C200); ; 
  putchar(10);        ; newline error-check
  if ( qword_CCC0 ) ; win condition
  {
    sub_3205("cypis", "Congrats, you got all the items!");
    sub_3205("cypis", "Not sure why I need them, I don't even drink alcohol.");
    sub_3205("cypis", "(Not since the incident)");
    sub_3205("cypis", "Anyway, good job! Here's your flag.");                    
    sub_32C8(&qword_CFC8, 16LL, 4LL); ; mangle function                  <-- point of interest
    puts(aEYqkl); ; putsing flag
    sub_3205("cypis", "See you at another finals.");
    getchar();
    sub_33F0(); ; exit
  }
  if ( *(_BYTE *)(qword_D068 + 2) == 32 ) ; progress condition
  {
    sub_3205("cypis", "What are you waiting for? Go!");
  }
  else ; nothing condition
  {
    sub_3205("cypis", "Welcome traveler on your quest.");
    sub_3205("cypis", "Bring me five artifacts of great power and I'll reward you generously.");
    sub_3205("cypis", "The gate is now open. Go if you dare.");
    sub_3205("cypis", "...");
    sub_3205("cypis", "Don't worry, the challenges are not particularly hard.");
    sub_3205("cypis", "Actually this is just a token RE task for C reversing enthusiasts.");
    sub_3205("cypis", "Also I get to generate some ASCII art.");
    sub_3205("cypis", "Anyway, go on and bring me the items.");
    *(_BYTE *)(qword_D068 + 2) = 32;
  }
  return getchar();
}
```
The function checks for a win condition and puts the flag, the point of interest we can find is the `sub_32C8` function, which appears to mangle the flag data, I've pasted the function below, however understanding it is not essential to solving the challenge, just that we need to successfully call it where required, otherwise our flag data will be incorrect.
```c
__int64 __fastcall sub_32C8(__int64 a1, int a2, int a3)
{
  __int64 result; // rax
  unsigned int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = i;
    if ( (int)i >= a3 )
      break;
    aEYqkl[a2 + i] ^= *(_BYTE *)((int)i + a1);
  }
  return result;
}
```
We can check X-refs in IDA to see where the function is called, which we need to "complete" in the game by interacting with the corresponding characters in order to succesfully call the mangle function. After this, we can return to cypis for our flag, without having looked at the win condition, we can simply patch it if required as it does not affect our flag.

The characters that use the mangle function include the following, which I have labelled accordingly:  
```c
sub_3A55(): "D" - des
sub_3CFC(): "s" - sasza 
sub_38E5(): "M" - msm  
```
I have seperated each function into a part of the writeup, all 3 are required to solve the challenge, however the order is not relevant.

# Calculate
Challenge:
```c
sub_3A55(): "d" - des
```
This is the simplest function to reverse, where we "play a game" with `des` guessing a series of 10 numbers, in the interaction we enter a loop, each which checks our input against a newly modified number, if all compares succeed the mangle function is called and we exit, and if we fail a compare the function exits without mangling the flag. I've included the code with comments below:
```c
int sub_3A55()
{
  char v1[10]; // [rsp+6h] [rbp-7Ah] BYREF
  char nptr[100]; // [rsp+10h] [rbp-70h] BYREF
  int v3; // [rsp+74h] [rbp-Ch]
  int i; // [rsp+78h] [rbp-8h]
  int v5; // [rsp+7Ch] [rbp-4h]

  sub_3414();
  sub_3427(off_C640);
  putchar(10);
  sub_3205("des", "Let's play a game");
  sub_3205("des", "I will help you if you guess three numbers that I think of correctly"); ; diologue
  sub_3205("des", "Let's try that. What number am I thinking about?");
  v5 = 13; ; initialise v5 as 13
  for ( i = 0; i <= 9; ++i ) ; 10 number loop
  {
    sub_345C(nptr);
    v3 = atoi(nptr);
    v5 = (123 * v5 + 321) % 256; ; computing v5
    v1[i] = v5;
    if ( v3 != v5 ) ; comparing our inpit against v5
    {
      sub_3205("des", "No, that's wrong. Sorry, I can't help you."); ; fail condition
      return getchar();
    }
    sub_3205("des", "Correct! And now?"); ; correct condition
  }
  sub_3205("des", "Wow you're very smart."); ; win condition
  sub_3205("des", "I will fight for you.");
  byte_CFC0 = 1;
  qword_CFC8 += 322376503LL;
  *(_BYTE *)(qword_D0A0 + 49) = 32;
  sub_32C8(v1, 6LL, 10LL); ; flag mangle
  return getchar();
}
```
The loop simply performs a few operations on `v5`, before comparing it to our input `v3` 10 times, `v5` is initalised as `13` before we enter the loop, so we can simply start there and calculate each number in the loop to get the correct guesses. We also note that the result of each iteration is the new starting value of `v5` for the next iteration. With each iteration `v5` is multiplied by `123`, added `321` and mod `256`.

We can calculate the 10 numbers with a list comprehension in python:
```c
x = 13
[(x := ((x * 123) + 321) % 256) for _ in range(10)]
# [128, 193, 252, 85, 24, 201, 212, 29, 48, 81]
```
Interacting with `des` in the program and supplying the numbers, we hit the correct message 10 times before reaching the win condition and exiting.

# Code Optimisation
Challenge:
```c
sub_3CFC(): "s" - sasza 
```
This part of the challenge was possible to complete without reversing but simply time, however with the length of the CTF optimisation was much more successful. The premise of this challenge is that you must enter a password, there is a lose check that allows you to enter a "correct" password that will pass the compare, however data from the password is used in the flag mangling so it is essential to find the fully correct password. Luckily, `sasza` offers to tell us the password, however this is an incredibly slow process that we must optimise. I have commented the code below:
```c
int sub_3CFC()
{
  unsigned __int64 v0; // rcx
  char s1[6]; // [rsp+0h] [rbp-90h] BYREF
  _BYTE v3[106]; // [rsp+6h] [rbp-8Ah] BYREF
  unsigned __int64 j; // [rsp+70h] [rbp-20h]
  unsigned __int64 v5; // [rsp+78h] [rbp-18h]
  int i; // [rsp+84h] [rbp-Ch]
  unsigned __int64 v7; // [rsp+88h] [rbp-8h]

  sub_3414();
  sub_3427(off_C940);
  putchar(10);
  sub_3205("sasza", "I'll give you your drink if you tell me my secret password.");
  sub_3205("sasza", "To get the password you need to uhh...");
  sub_3205("sasza", "[Sasza thinks for a second about an easy RE challenge to give you]"); ; diologue
  sub_3205("sasza", "Fuck this, I'll just tell you the password right away");
  sub_3205("sasza", "Do you want to hear it (yes/no)?");
  sub_345C(s1);
  if ( !strcmp(s1, "yes") ) ; selection
  {
    sub_3205("sasza", "Here it goes:");
    v7 = 1LL;
    for ( i = 0; i <= 29; ++i )
    {
      v5 = 0LL;
      printf(" %lx\n", v7);             ; password read
      for ( j = 0LL; j < v7; ++j )
      {
        v0 = v5 + 29;
        v5 = (v5 + 29) / 0x2AAAAAAB;
        v5 = v0 - 715827883 * v5;
      }
      putchar(v5 % 0x14 + 97);
      fflush(stdout);
      v7 *= 4LL;             ; (slow)
    }
  }
  else
  {
    sub_3205("sasza", "Uhhh, ok?");                                          *ida misinterpreted types (v3)
  }
  sub_3205("sasza", "Anyway, give me the password or leave me alone");
  sub_345C(s1);
  if ( strlen(s1) == 30 && s1[0] == 106 && v3[23] == 103 ) ; lose password comparison, win condition
  {
    sub_3205("sasza", "Yeah, it looks similar. Just don't cheat here or your flag will be broken.");
    *(_BYTE *)(qword_D030 + 42) = 32;
    sub_3259("suspicious moonshine (70%)");
    sub_32C8(v3, 0LL, 30LL); ; mangle flag
  }
  else
  {
    sub_3205("sasza", "No, did you even listen to what I've said?"); ; fail condition
  }
  return getchar();
}
```
The password comparison only checks for the string length being 32, and indexes [0] as the character 'j' and [23] as the character 'g', with this knowledge we can create a string that passes such as `"j_p4ctfisverycool_g_flagpls_lol!"`. This passes, however has the wrong data passed into the flag mangle function.

Selecting "yes" to listen to the password begins to slowly output the fully correct password, however the time between each character grows exponentially, GPT-4 was able to optimise the code to print the full password without the significant delays:
```c
#include <stdio.h>

void optimised()
{
    long long v6 = 1LL;
    int i;

    for (i = 0; i <= 29; ++i)
    {
        // printf(" %llx\n", v6);

        long long v0 = 29LL;
        long long v4 = v0 / 0x2AAAAAAB;
        v4 = v0 - 715827883 * v4;
        v4 = v4 * v6 % 0x2AAAAAAB;

        putchar(v4 % 0x14 + 97);
        fflush(stdout);
        v6 *= 4LL;
    }
}

int main()
{
    optimised();
    putchar(10);

    return 0;
}
// jqeqeqeqeqeqekohflplplplplplsg
```
This outputs `jqeqeqeqeqeqekohflplplplplplsg`, which not only passes the password check however we assume is the fully correct data to be passed to the mangle flag function. We can supply this password to `saszy` in the interaction.

# Pigeon Patch
Challenge:
```c
sub_38E5(): "m" - msm  
```
This challenge was the most difficult, as `msm` did not directly accept input from us and we needed to reverse an encyrption function to find the correct value that was expected for our win condition. Once we reverse the encryption function we can patch the correct value in memory. The decrypted value is also passed to the flag mangle function, so we cannot just patch the condition. The main function is commented below:
```c
int sub_38E5()
{
  sub_3414();
  sub_3427(off_C440);
  putchar(10);
  if ( strlen(s1) <= 6 && sub_38A2(s1) == 0xC67A3A1D8F87DLL ) ; encrypt s1 and compare against value
  {
    sub_3205("msm", "[msm snatches the food from your hands and disappears]"); ; win condition
    sub_3205("msm", "[you take a look at the place where msm used to be and notice something]");
    sub_3259("kuflowe mocne 7.2%");
    sub_32C8(s1, 0LL, 6LL); ; flag mangle 
    *(_BYTE *)(qword_D098 + 15) = 32;
  }
  else
  {
    sub_3205("msm", "[msm is not pleased with you and says nothing]"); ; fail condition
  }
  return getchar();
}
```
Note that there is no user input, and that we must dynamically edit whats in memory to hit the win condition. The encryption function sub_38A2() takes the value of `s1`, encrypts, and compares it to a value (0xC67A3A1D8F87D). The encryption function is below:
```c
unsigned __int64 __fastcall sub_38A2(_BYTE *a1)
{
  _BYTE *v1; // rax
  unsigned __int64 v4; // [rsp+10h] [rbp-8h]

  v4 = 0LL;
  while ( *a1 )
  {                          ; encryption
    v1 = a1++;
    v4 = (char)(*v1 ^ 0x13) ^ (v4 << 9);
  }
  return v4;
}
```
The encryption performs a few simple operations on the argument and returns a new value, we can write a decryption function and pass the compared value from the calling function to see what value is expected to hit the win condition:
```c
#include <stdio.h>
#include <stdlib.h>

char* unencrypt(unsigned long long output)
{
    char* a1 = (char*)malloc(sizeof(char));
    int length = 0;

    while (output != 0)
    {
        char v1 = output ^ 0x13;
        length++;
        a1 = (char*)realloc(a1, length * sizeof(char));
        a1[length - 1] = v1;
        output = output >> 9;
    }

    char* plain = (char*)malloc((length + 1) * sizeof(char));
    for (int i = length - 1; i >= 0; i--)
    {
        plain[length - 1 - i] = a1[i];
    }
    plain[length] = '\0';

    free(a1);

    return plain;
}

int main()
{
    unsigned long long encrypted = 0xC67A3A1D8F87D;
    char* plain = unencrypt(encrypted);
    printf("%s\n", plain);

    free(plain);

    return 0;
}
// pigeon
```
Running this returns the string `piegon`, which is the correct value we need to hit the win condition. In order to pass this check, we can set `s1` in memory before the compare. To do this we can use GDB, firstly breaking on `msm`s function call, then patching the memory before continuing. We can prepare the file in GDB as below: (Note: I will be using `pwndbg`)
```c
torry@twooo$ gdb-pwndbg -q demo -ex "starti" -ex "vmmap"
```
We can locate the offset of the `msm`s function in IDA and find it is `38E5`, using the output of `vmmap` from our setup above we can calculate and set the breakpoint.
```c
pwndbg> break * (0x<start_addr>+0x38E5)
```
From here we can continue and GDB will break when we interact with `msm`.  I've commented how we patch the memory below:
```c
pwndbg> set $s1=(0x555555554000+0xcc20) ; define s1
pwndbg> set *(long*)(0x555555554000+0xcc20)=0x00006e6f65676970 ; set s1 to "pigeon" (swapped endianess)
pwndbg> x/gx $s1 ; confirm s1 value is correct
0x555555560c20: 0x00006e6f65676970
pwndbg> x/gs $s1
warning: Unable to display strings with size 'g', using 'b' instead.
0x555555560c20: "pigeon"
```
From here we can simply continue in GDB and the check passes and we hit our win condition.

# Conclusion
After patching the memory for `msm` and entering the correct password and values for `saszy` and `des` we can return to `cypis` to get our flag, we can easily patch cypis to give us the flag or complete the interactions with the other characters which comes with the benefit of appreciating the ascii art.

This was a simple challenge with interesting elements, the program was well made and without the time constraint of the event it can be further explored to understand its inner workings. The flag output (redacted) is below:
```c
<cypis> Congrats, you got all the items!
<cypis> Not sure why I need them, I don't even drink alcohol.
<cypis> (Not since the incident)
<cypis> Anyway, good job! Here's your flag.
<REDACTED>
<cypis> See you at another finals.
Game over :(
```
The p4] CTF Finals 2023 was an amazing event with a lot of great challenges. (and ASCII art)

I emphasize a huge props to the [organisers](https://p4.team) for running both the qualifiers and finals and providing myself and my [team](https://emu.team/about) with the opportunity of our first international finals [event](https://ctftime.org/event/2020). 

I would also like to credit my teammates [bradan](https://bradan.dev), [teddy](https://thesavageteddy.github.io) and escpecially [toasterpwn](https://toasterpwn.github.io) for collaborating on the challenges including this one.

Travelling the ~50 hours from down under to Katowice Poland to play in person was a truly great experience and we hope to join p4 again next year.

![p4ctf2023woooooo](/scoundrelike/event.png)

---------------- 

--> Share via <a href="https://torrytw.ooo/index/p4-ctf-finals-scoundrelike-re/">link</a>  
--> Return to the <a href="https://torrytw.ooo/index/">Index</a>

