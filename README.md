Name
====

ngx_http_lua_client - Nginx C module to access ngx_lua to execute the Lua code by a client.


Table of Contents
=================

* [Name](#name)
* [Installation](#installation)
* [Directives](#directives)


Installation
============

This module is not default in the Openresty

You can add like :
```
    ... ...
    [http_lua_upstream => 'ngx_lua_upstream'],
    [http_lua_client => 'ngx_lua_client'],
    [http_headers_more => 'headers-more-nginx-module'],
    ... ...
```

And add ngx_lua_client* direction in your bundle/, then just `configure` your openresty.


Directives
==========
We have some ngxin setting, to set the connect host and port:

* [lua_client_host](#lua_client_host)
* [lua_client_port](#lua_client_port)

And you can execute the lua-script through below command:

* [execute lua-script](#execute lua-script)
* [execute lua-file](#execute lua-file)

lua_client_host
---------------
**syntax:** *lua_client_host ip*

**default:** *lua_client_host 127.0.0.1*

**context:** *http*

Set the connection host.

lua_client_port
---------------
**syntax:** *lua_client_port port*

**default:** *lua_client_port 8220*

**context:** *http*

Set the connection port.

execute lua-script
-------------

```
    ./resty-client -h 127.0.0.1 -p 8820 -e lua-script
```

execute lua-file
-------------

```
    ./resty-client -h 127.0.0.1 -p 8820 -f lua-file
```

