# Mark sections

Zones are bound to the scope of a function or a block, but your program's big-picture phases are not. For those, use [sections](#markingsections): `TracySectionEnter( "Loading level %d", level )` marks the start and returns an identifier you store, and `TracySectionLeave( id )` marks the end, even when the two calls sit in completely different places. Every section is tracked independently, so sections may overlap, nest, or leave gaps: a main menu section, one section per level, and so on.

Sections can be organized into categories. `TracySectionSetup( category, "Game levels" )` gives a category a name, and `TracySectionEnterCategory( category, ... )` starts a section inside it. Sections started with plain `TracySectionEnter` end up in category 0. Categories let you filter out the noise later. For example, when you care about level progression, you can hide the inventory-screen sections instead of sifting through them.

Sections appear in their own lane at the top of the timeline, above all the threads, as a high-level view of what your program is doing at any moment. Middle-click a section bar to zoom the view straight to its span.

Mark the main phases of your application, start them with `TracySectionEnter` and end them with `TracySectionLeave`, then middle-click your way through the section lane to examine each phase up close. Try it out!
