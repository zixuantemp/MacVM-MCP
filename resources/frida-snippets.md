# Frida Snippets for macOS

Drop-in JavaScript snippets for `frida_run_script` / `frida_spawn_and_attach`.

## NSURLSession — log every HTTP(S) request
```javascript
var NSURLSession = ObjC.classes.NSURLSession;
Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
    onEnter: function(args) {
        var req = new ObjC.Object(args[2]);
        console.log('[URL] ' + req.URL().absoluteString().toString());
        var headers = req.allHTTPHeaderFields();
        if (headers) console.log('[HDR] ' + headers.toString());
        var body = req.HTTPBody();
        if (body) console.log('[BODY] ' + body.toString());
    }
});
```

## NSFileManager — log file operations
```javascript
['createFileAtPath:contents:attributes:',
 'removeItemAtPath:error:',
 'copyItemAtPath:toPath:error:',
 'moveItemAtPath:toPath:error:'].forEach(function(sel) {
    var m = ObjC.classes.NSFileManager['- ' + sel];
    if (m) Interceptor.attach(m.implementation, {
        onEnter: function(args) {
            console.log('[FS] ' + sel + ' path=' + new ObjC.Object(args[2]).toString());
        }
    });
});
```

## NSTask — log child process spawns
```javascript
var NSTask = ObjC.classes.NSTask;
Interceptor.attach(NSTask['- launch'].implementation, {
    onEnter: function() {
        var path = this.self.launchPath();
        var args = this.self.arguments();
        console.log('[NSTask] ' + path + ' ' + (args ? args.toString() : ''));
    }
});
```

## posix_spawn / execve / fork
```javascript
['posix_spawn', 'posix_spawnp', 'execve', 'execvp', 'fork', 'system'].forEach(function(fn) {
    var addr = Module.findExportByName(null, fn);
    if (addr) Interceptor.attach(addr, {
        onEnter: function(args) {
            console.log('[SPAWN] ' + fn + ' arg0=' + (args[0] ? Memory.readCString(args[0]) : '?'));
        }
    });
});
```

## CommonCrypto — capture AES keys
```javascript
var CCCrypt = Module.findExportByName('libSystem.B.dylib', 'CCCrypt');
Interceptor.attach(CCCrypt, {
    onEnter: function(args) {
        // op, alg, options, key, keyLength, iv, dataIn, dataInLength, ...
        var keyLen = args[4].toInt32();
        console.log('[CCCrypt] op=' + args[0] + ' keyLen=' + keyLen);
        console.log('[CCCrypt] key=' + hexdump(args[3], {length: keyLen}));
        if (!args[5].isNull())
            console.log('[CCCrypt] iv =' + hexdump(args[5], {length: 16}));
    }
});
```

## SSL pinning bypass (NSURLSession)
```javascript
var URLSessionDelegate = ObjC.protocols.NSURLSessionDelegate;
var sel = '- URLSession:didReceiveChallenge:completionHandler:';
ObjC.classes.NSObject['- ' + sel] && Interceptor.replace(
    ObjC.classes.NSObject['- ' + sel].implementation,
    new NativeCallback(function(self, _cmd, session, challenge, handler) {
        var trust = new ObjC.Object(challenge).protectionSpace().serverTrust();
        var cred = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
        new NativeFunction(handler, 'void', ['int', 'pointer'])(0, cred);
    }, 'void', ['pointer','pointer','pointer','pointer','pointer'])
);
```

## TCC database access
```javascript
var sqlite3_exec = Module.findExportByName(null, 'sqlite3_exec');
Interceptor.attach(sqlite3_exec, {
    onEnter: function(args) {
        console.log('[sqlite3_exec] ' + Memory.readCString(args[1]));
    }
});
```

## Module load tracing
```javascript
Process.setExceptionHandler(function() { return false; });
var dlopen = Module.findExportByName(null, 'dlopen');
Interceptor.attach(dlopen, {
    onEnter: function(args) {
        console.log('[dlopen] ' + (args[0].isNull() ? '(self)' : Memory.readCString(args[0])));
    }
});
```
