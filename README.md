Process Doppelgänging
==========
[![Build status](https://ci.appveyor.com/api/projects/status/mnoqdw09gs96mih5?svg=true)](https://ci.appveyor.com/project/hasherezade/process-doppelganging)

This is my implementation of the technique presented by enSilo:<br/>
https://www.youtube.com/watch?v=Cch8dvp836w

![](https://blog.malwarebytes.com/wp-content/uploads/2018/08/dopel1_.png)

Characteristics:
-

+ Payload mapped as `MEM_IMAGE` (unnamed: not linked to any file)
+ Sections mapped with original access rights (no `RWX`)
+ Payload connected to PEB as the main module
+ Remote injection supported (but only into a newly created process)
+ Process is created from an unnamed module (`GetProcessImageFileName` returns empty string)

<hr/>
<b>WARNING:</b> <br/>
The 32bit version works on 32bit system only. 
