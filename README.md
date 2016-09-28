Name
====

ngx_http_lua_client - Nginx C module to access ngx_lua to execute the Lua code.


Table of Contents
=================

* [Name](#name)
* [Installation](#installation)
* [Functions](#functions)


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


Functions
=========

./resty-client -e CODE

./resty-client -f FILENAME

