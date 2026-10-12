# Chart values

Some questions are not about how long things take, but about how a number changes over time: draw calls per frame, queries in flight, queue depth. Use [plots](#plottingdata): `TracyPlot( "draw calls", count )` reports one point each time it is called, and the points become a plot lane below the threads in the timeline, where spikes and trends are easy to spot at a glance. Middle-click the plot header to zoom the view straight to the range the plot has recorded.

`TracyPlotConfig( name, type, step, fill, color )` is optional: pick a number format (`Number`, `Memory`, `Percentage`), hold values as a staircase instead of a smooth line, fill the area under the curve, or set the line color.

Pick a number that matters to your application, report it with `TracyPlot`, then middle-click the plot header to see its full span. Try it out!
