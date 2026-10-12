# Analyze contention

The [Lock info window](#lockwindow) shows how a lock spends its life. Compare `Lock hold time` against `Lock wait time`. A lock that is held only a little but waited on a lot is a queue, not a workspace. `Max waiting threads` tells you how long that queue gets at its worst, and expanding `Thread list` shows every thread using the lock.

When threads are left waiting for each other with no way out, the window flags it as a [deadlock](#deadlockdetection) and names the threads involved.

Open one of your locks and check the hold against wait split. Try it out!
