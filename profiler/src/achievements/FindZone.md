# Find some zones

You can search for zones in the trace by opening the search window with the * Find zone* button on the top bar. It will ask you for the zone name, which in most cases will be the function name in the code.

The search may find more than one zone with the same name. A list of all the zones found is displayed, and you can select any of them.

Alternatively, you can open the Statistics window and click an entry there. This will open the Find zone window as if you had searched for that zone.

When a zone is selected, a number of statistics are displayed to help you understand the performance of your application. In addition, a histogram of the zone execution times is displayed to make it easier for you to determine the performance of the profiled code. Be sure to select a zone with a large number of calls to make the histogram look interesting!

Note that you can draw a range on the histogram to limit the number of entries displayed in the zone list below. This list allows you to examine each zone individually. There are also a number of zone groupings that you can select. Each group can be selected and the time associated with the selected group will be highlighted on the histogram.
