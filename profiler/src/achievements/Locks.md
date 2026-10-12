# Watch locks

When something runs slowly, the thread may not be working at all: it could be waiting on a mutex. To see that, declare your synchronization objects with the [Tracy wrappers](#markinglocks) instead of the raw type: `TracyLockable( std::mutex, resourceMutex )` for exclusive locks and `TracySharedLockable( std::shared_mutex, assetLock )` for shared ones. The `*N` variants, such as `TracyLockableN( std::mutex, resourceMutex, "Assets" )`, let you pick the name the lock is displayed under. Code that receives a lock reference works with the wrappers through `LockableBase`/`SharedLockableBase`:

```c++
void Update( LockableBase( std::mutex )& mutex )
{
    std::lock_guard guard( mutex );
    // ...
}
```

Instrumented locks show up as lanes in each thread's timeline row. Hover over a lock event to see the important information, for example which threads are blocking it and which ones it blocks, then left-click the event to open the [Lock info window](#lockwindow), with the lock's location, type, and event count. Middle-click an event to zoom the view to its extent. Wrap a few of your mutexes, profile the application, and click through your first lock. Try it out!
