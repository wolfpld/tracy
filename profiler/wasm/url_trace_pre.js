// Startup trace loader: fetches ?t=<url>, or embed.tracy next to the page when no
// URL is given, into the /url.tracy virtual file.
if( typeof document !== 'undefined' )
{
    const tracyTraceParam = new URLSearchParams( window.location.search ).get( 't' );
    let tracyUrl = null;
    let tracyUrlError = null;
    if( tracyTraceParam )
    {
        try { tracyUrl = new URL( tracyTraceParam, window.location.href ); }
        catch( e ) { tracyUrlError = 'invalid URL'; }
        if( tracyUrl && ( ( tracyUrl.protocol !== 'https:' && tracyUrl.protocol !== 'http:' ) ||
                          tracyUrl.username !== '' || tracyUrl.password !== '' ) )
            tracyUrlError = 'unsupported URL (https/http without embedded credentials required)';
    }
    else
    {
        tracyUrl = new URL( 'embed.tracy', window.location.href );
    }

    const isTracyFile = ( b ) => b.length >= 4 && (
        ( b[0] === 0x74 && b[1] === 0x72 && b[2] === 0xfd && b[3] === 0x50 ) ||
        ( b[0] === 0x74 && b[1] === 0x6c && b[2] === 0x5a && b[3] === 0x04 ) ||
        ( b[0] === 0x74 && b[1] === 0x5a && b[2] === 0x73 && b[3] === 0x74 ) );

    const tracyTraceData = ( () =>
    {
        if( tracyUrlError ) return Promise.reject( tracyUrlError );
        const opts = { mode: 'cors' };
        if( tracyTraceParam && tracyUrl.protocol === 'http:' )
        {
            const loopback = tracyUrl.hostname === 'localhost' || tracyUrl.hostname.endsWith( '.localhost' ) ||
                             tracyUrl.hostname === '[::1]' || /^127\./.test( tracyUrl.hostname );
            // Local Network Access: pre-resolve classification, relaxes mixed content for local targets.
            opts.targetAddressSpace = loopback ? 'loopback' : 'local';
        }
        const ctrl = new AbortController();
        opts.signal = ctrl.signal;
        const timeout = setTimeout( () => ctrl.abort(), 300000 );
        Module.setStatus( 'Loading trace...' );
        return fetch( tracyUrl.href, opts ).then( ( resp ) =>
        {
            if( !resp.ok ) { clearTimeout( timeout ); throw 'HTTP status ' + resp.status; }
            const total = Number( resp.headers.get( 'Content-Length' ) || 0 );
            if( !resp.body || !total )
            {
                return resp.arrayBuffer().then(
                    ( ab ) => { clearTimeout( timeout ); return new Uint8Array( ab ); },
                    ( e ) => { clearTimeout( timeout ); throw e; } );
            }
            const reader = resp.body.getReader();
            const chunks = [];
            let received = 0;
            const pump = () => reader.read().then( ( { done, value } ) =>
            {
                if( done )
                {
                    clearTimeout( timeout );
                    const out = new Uint8Array( received );
                    let off = 0;
                    for( const c of chunks ) { out.set( c, off ); off += c.length; }
                    return out;
                }
                chunks.push( value );
                received += value.length;
                Module.setStatus( 'Loading trace (' + received + '/' + total + ')' );
                return pump();
            } );
            return pump();
        },
        ( e ) => { clearTimeout( timeout ); throw ( e && e.name === 'AbortError' ) ? 'download timed out' : 'fetch failed'; } );
    } )();

    Module.preRun = Module.preRun || [];
    Module.preRun.push( () =>
    {
        addRunDependency( 'tracy-startup-trace' );
        tracyTraceData.then(
            ( bytes ) =>
            {
                if( !isTracyFile( bytes ) )
                {
                    FS.writeFile( '/url.tracy.failed', new Uint8Array( 0 ) );
                    alert( 'Cannot load trace from ' + tracyUrl.href + ': not a Tracy trace file' );
                }
                else FS.writeFile( '/url.tracy', bytes );
            },
            ( err ) =>
            {
                FS.writeFile( '/url.tracy.failed', new Uint8Array( 0 ) );
                alert( 'Cannot load trace from ' + tracyUrl.href + ': ' + err );
            } ).finally( () => removeRunDependency( 'tracy-startup-trace' ) );
    } );
}
