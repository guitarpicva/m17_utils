README.md for m17_utils repository

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
PLEASE TEST THIS BEFORE YOU PUT IT INTO A PROJECT
AS THE FIRST RELEASE HAS YET TO BE VALIDATED.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Basic utilities for use with the M17Project.org for framing
data into/out of an M17 compatible modem.

Includes so far:

CRC generation

Address conversion to base 40 notation

Link Setup Frame generation at least for Qt

Coming soon:

Data Frame generation


To use, include the m17_utils and one of c, cpp, or qt
depending on your project needs.

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

PLEASE TAKE NOTE THAT FOR THE TIME BEING:
The main.cpp file includes some Qt libraries and
the CMakeLists.txt also includes Qt6::Core.  That is for
ease of testing for me.

Naturally, you can cut out what you don't need as required
for your project.
