

PPC Altivec v1.8 for IDA

(aka Xbox360, PS3, Gamecube, Wii support for IDA)



:: Overview

This plugin for IDA originally written by Dean Ashton to add support
for Altivec/VMX instructions to IDAs normal PPC processor module.

Dean did the hard work in creating and setting up this plugin,
and since then many other people including myself have taken advantage
of the existing sourcecode to add more instructions and tweaks to
support a variety of other special instructions. It now supports
the extra instructions used by Xbox360, PS3, Gamecube and Wii,
as well as the original Altivec and VMX instructions.




:: Install

To install this, copy all files into the "IDA\plugins" directory.

If you have the Gamecube "Gekko CPU Extension" plugin by HyperIris
installed you will need to remove it before using this plugin as
otherwise they will clash with each other. This plugin now implements
all features of the Gekko plugin anyway.



