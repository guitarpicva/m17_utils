README.md for m17_utils repository

Basic utilities for use with the M17Project.org for framing
data into/out of an M17 compatible modem.

Includes so far:

CRC generation

Address conversion to base 40 notation

Coming:

Link Setup Frame generation

Data Frame generation

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

PLEASE TAKE NOTE THAT FOR THE TIME BEING:
The header file includes some Qt libraries and
the CMakeLists.txt also includes Qt6::Core.  I will be 
splitting the Qt specific utils out into their own header
shortly.  Then a stdlib version for C++ only, and the 
remainder will be C compatible.

Naturally, you can cut out what you don't need from 
the existing m17_utils.h as required for your project.
