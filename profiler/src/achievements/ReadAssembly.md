# Assembly required

Tracy copies more than source files into the trace. It also copies your program's machine code: the exact instructions your functions were compiled into. The source view can therefore show you what each line you wrote was turned into. Choose *Source* only, machine *Assembly* only, or *Both* side by side with the *Mode* selector at the top of the window.

To see which instructions matter, enable [call stack sampling](#sampling). Tracy then interrupts the program repeatedly and records where in the code it was interrupted. Every instruction gets a percentage showing how often the interruptions caught it running. The instructions caught running most often are the ones eating your time; you can spot them by their percentages. The brightest are the hottest.

The compiler inlines calls, fuses loops, and reorders instructions, so a harmless-looking source line can hide the instruction that eats up the time.

Open the source view for a function you want to speed up and read its instructions. Try it out!
