# Log messages

Your debug output is worth keeping in the [trace log](#messagelog), not just on the console. `TracyMessageL( "config loaded" )` takes a string literal, `TracyMessage` takes a pointer and a size, and the `C` variants add a color so an entry stays findable in a long log.

All four always log with `Info` severity. `Warning` and `Error` are only reachable through `TracyLogString( severity, color, depth, txt )`, the underlying log call they all share. Most programs wrap it in their own small macros. Message macros with the `S` postfix capture a call stack as well.

The *  Messages* button on the top bar opens the [Messages window](#messages). Every message gets a row with its time, thread, text and stack. Hovering a row highlights it on the timeline, clicking centers the view. Log something and look at the list!
