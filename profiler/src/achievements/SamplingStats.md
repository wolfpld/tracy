# Read sampling statistics

The * Sampling* mode of the [Statistics window](#statistics) resembles instrumentation mode, but it reads a different source: [call stack samples](#statisticssampling). The counts are rough, so trust the ranking over the numbers.

The rows list symbols, not functions: a symbol is a base function plus everything inlined into it. Expand a name to see the inlines, merge separate copies with *Aggregate*, show the busiest inline instead with *Top inline*, or drop the grouping entirely with *Inlines*. Red rows are kernel samples: your thread running inside the kernel. Enable `External` to also list samples from external libraries.

Left-click a name to open the symbol view, or right-click it for the sample entry stacks. Switch to sampling mode and compare what changes. Try it out!
