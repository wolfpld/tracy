# Open entry stacks

The statistics list shows a symbol is hot. To see who keeps calling it, open the *Sample entry stacks* window. It shows [every call path](#stackwindows) that led to the symbol, weighted by how often each path was sampled.

Choose what counts: `Was reached` when the symbol appears anywhere in the stack, `Was reached, recursive` to count re-entrant calls separately, `Was executing` to keep only samples taken while it ran. The paths display as a flat list sorted by frequency, or as collapsible bottom-up/top-down trees.

You can open the window from the popup on a symbol name, from the * Entry stacks* button in the symbol view, or, in [assembly](#assemblymode) mode, by middle-clicking a hot instruction's sample share, a direct way to ask how execution reached a line. Open the entry stacks of your hottest symbol and read the top path. Try it out!
