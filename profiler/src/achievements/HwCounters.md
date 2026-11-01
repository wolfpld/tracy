# Hardware counters

Call-stack sampling says which lines cost the most time. A hot line might be doing a lot of arithmetic, or it might be stalled waiting on memory. Performance counters track cycles, branch mispredictions, and cache misses per instruction. When the kernel makes them available, Tracy collects them by default on Linux (WSL2 included) and Android, with no need to run the application as an administrator ([hardware sampling](#hardwaresampling)).

When the data is present, the toolbar of the [source view](#sourceview) shows a hardware row: a * Cost* dropdown re-ranks lines by a different counter, a * HW* switch adds IPC, branch, and cache columns, and an * Impact* switch changes what the branch and cache columns report. The dropdown starts at "Sample count", the software sampling you know. "Cycles" is its hardware-collected equivalent, and "Branch impact" and "Cache impact" weigh miss counts by how many events happened.

The higher the IPC, the more work the core does per cycle, and a low value means it spends cycles waiting, usually on memory. The branch and cache columns report misprediction and cache miss rates. With Impact off, those columns show isolated rates, which mislead when the sample is small: 100% misses on ten accesses is nothing compared to 50% on two thousand. Numbers based on only a handful of samples are shown dimmed, because there is not enough data behind them to be trusted.

Try opening the source view on a hot function and re-rank its lines by cycles.
