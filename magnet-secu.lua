-- /usr/local/etc/lighttpd/magnet-secu.lua _date: 20100919-1713_
-- vim: set filetype=lua ts=4:
-- -*- mode: lua; -*-
--
-- see
-- /src/bulk/http/server/lighttpd/lighttpd-1.4.27/doc/magnet.txt
-- /mnt/backup/no-backup/downloads/lua-lighttpd-mod_magnet-AbsoLUAtion.txt
-- http://blog.innerfence.com/2008/05/31/presto-move-content-to-s3-with-no-code-changes/
-- {{{
-- static const magnet_env_t magnet_env[] = {
--         { "physical.path", MAGNET_ENV_PHYICAL_PATH },
--         { "physical.rel-path", MAGNET_ENV_PHYICAL_REL_PATH },
--         { "physical.doc-root", MAGNET_ENV_PHYICAL_DOC_ROOT },
--         { "uri.path", MAGNET_ENV_URI_PATH },
--         { "uri.path-raw", MAGNET_ENV_URI_PATH_RAW },
--         { "uri.scheme", MAGNET_ENV_URI_SCHEME },
--         { "uri.authority", MAGNET_ENV_URI_AUTHORITY },
--         { "uri.query", MAGNET_ENV_URI_QUERY },
--         { "request.method", MAGNET_ENV_REQUEST_METHOD },
--         { "request.uri", MAGNET_ENV_REQUEST_URI },
--         { "request.orig-uri", MAGNET_ENV_REQUEST_ORIG_URI },
--         { "request.path-info", MAGNET_ENV_REQUEST_PATH_INFO },
--         { "request.remote-ip", MAGNET_ENV_REQUEST_REMOTE_IP },
--         { "request.protocol", MAGNET_ENV_REQUEST_PROTOCOL },
-- };
-- }}}

--[[--
NB: the only user servicable part is the configuration table
"trigger_patterns[]" later in this theater.  Some craft comes before
that for technical reasons:  that table needs values that must be
defined earlier.
--]]--

local iam = "etc/lighttpd/magnet-secu.lua"
-- /etc/modprobe.d/modprobe.conf
-- options xt_recent ip_list_tot=555 ip_pkt_list_tot=33 ip_list_gid=33 ip_list_perms=0664
local firewall_block = "/proc/net/xt_recent/hole"
local doc_root = lighty.env["physical.doc-root"] or "/home/www/doc"
local ip_exceptions = {
    "^127%.",
}

-- mod_security alike in LUA for mod_magnet
LOG = 1
DROP = true

-- selectors that can be used in the trigger_patterns[] rule table
local l_remote_ip = { "env", "request.remote-ip" }
local l_host = { "request", "Host" }
local l_method = { "env", "request.method" }
local l_orig_uri = { "env", "request.orig-uri" }
local l_uri = { "env", "request.uri" }
local l_user_agent = { "request", "User-Agent" }
local l_uri_authority = { "env", "uri.authority" }
local l_uri_query = { "env", "uri.query" }
local l_uri_scheme = { "env", "uri.scheme" }

-- grab request values from lighty environment
local unknown_authority = "UNKOWN_AUTHORITY"
local unknown_host = "UNKNOWN_HOST"
local unknown_ip = "UNKNOWN_IP"
local unknown_method = "UNKNOWN_METHOD"
local unknown_orig_uri = "UNKNOWN_ORIG_URI"
local unknown_uri = "UNKNOWN_URI"
local unknown_user_agent = "UNKNOWN_USER_AGENT"
local remote_ip = lighty[l_remote_ip[1]][l_remote_ip[2]] or unknown_ip
local request_host = lighty[l_host[1]][l_host[2]] or unknown_host
local request_method = lighty[l_method[1]][l_method[2]] or unknown_method
local request_uri = lighty[l_uri[1]][l_uri[2]] or
    lighty[l_orig_uri[1]][l_orig_uri[2]] or unknown_uri
local request_user_agent = lighty[l_user_agent[1]][l_user_agent[2]] or unknown_user_agent
local uri_authority = lighty[l_uri_authority[1]][l_uri_authority[2]] or unknown_authority
local uri_scheme = lighty[l_uri_scheme[1]][l_uri_scheme[2]] or "http"
local uri_query = lighty[l_uri_query[1]][l_uri_query[2]] or ""

local function logg(level, mess)
    if LOG >= level then
        print(iam .. ": " .. mess)
    end
    return true
end

-- zero means: return nil, continue request w/o Lua.
local ret_code = 0
local match = string.match
local gsub = string.gsub

-- "nil", "number", "string", "boolean", "table", "function", "thread", "userdata"

local function except_ip(ip)
    local excepted = false
    local mess
    local idx, ip_p, t_ip_p
    for idx, ip_p in ipairs(ip_exceptions) do
        t_ip_p = type(ip_p)
        if t_ip_p == "string" then
            excepted = match(ip, ip_p)
            if excepted then break end
        else
            logg(0, "ip_exceptions[" .. idx .. "]: must be string: " .. t_ip_p)
        end
    end
    mess = (excepted and "excepted: " or "blocked: ") .. remote_ip
    -- note that strings count as true in Lua
    return excepted, mess
end

local function block_ip(reason)
    local ex = true
    local excepted, mess = except_ip(remote_ip)
    mess = mess .. ": (" .. reason .. ") -- "
    mess = mess .. request_method .. " " .. uri_authority .. " " .. request_uri
    if DROP and (remote_ip ~= unknown_ip) and not excepted then
        -- local block_file, err = io.open(firewall_block, "w")
        local block_file, err = io.open(firewall_block, "a")
        ex = true
        mess = mess .. " -- " .. firewall_block
        if not block_file then
            mess = mess .. ": " .. err
            ex = false
        else
            mess = mess .. " +" .. remote_ip
            block_file:write("+" .. remote_ip .. "\n")
            block_file:close()
        end
    end
    logg(1, mess)
    return ex
end

local moved_301_pre = [[
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="]]
local moved_301_post = [[
">here</a>.</p>
</body></html>
]]
res_reflect = function(text, block)
    local new_request
    -- why doesn't this work?
    -- local host, host_port = match(uri_authority, "^(.+)(%:.*)?$")
    local host, host_port = match(uri_authority, "^(.-)(:.*)$")
    if not host then
        host = remote_ip
    else
        host = remote_ip .. host_port
    end
    if block then block_ip(text) end
    new_request = uri_scheme .. "://" .. host .. request_uri
    -- lighty.header[""] = ""
    -- lighty.header["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate, post-check=0, pre-check=0"
    lighty.header["Cache-Control"] = "max-age=0, no-cache, no-store"
    lighty.header["Connection"] = "close"
    -- lighty.header["Connection"] = "Keep-Alive"
    lighty.header["Content-Type"] = "text/html; charset=iso-8859-1"
    -- lighty.header["Content-Type"] = "text/html; charset=UTF-8"
    lighty.header["Expires"] = "Thu, 16 Sep 2010 17:33:08 GMT"
    lighty.header["Keep-Alive"] = "timeout=20, max=968"
    lighty.header["Location"] = new_request
    lighty.header["Pragma"] = "no-cache"
    lighty.header["Server"] = "Apache-kakka"
    lighty.header["Status"] = "301 Moved Permanently"
    lighty.header["X-Backend-Server"] = "popl-web02"
    lighty.header["X-Cache-Info"] = "cached"
    -- lighty.header["X-Cache-Info"] = "not cacheable; response is 302 without expiry time"
    lighty.header["X-Powered-By"] = "PHP/5.2.9"
    lighty.content = { moved_301_pre .. new_request .. moved_301_post }
    -- return 302
    return 301
end
res_block = function(text, block)
    if block then block_ip(text) end
    lighty.header["Content-Type"] = "text/plain"
    lighty.content = { "blocked" }
    return 405
end
--[[--
{{{
17:40:09 2010-09-17 17:40:09: (log.c.175) server started
17:40:20 2010-09-17 17:40:20: (request.c.304) fd: 5 request-len: 249
17:40:20 GET /manager/html HTTP/1.1.
17:40:20 Host: 127.0.0.1.
17:40:20 User-Agent: Lynx/2.8.5 (Compatible; ELinks).
17:40:20 Referer: http://127.0.0.1/manager/html.
17:40:20 Accept: */*.
17:40:20 Connection: Keep-Alive.
17:40:20 If-Modified-Since: Mon, 14 Jun 2010 22:16:12 GMT.
17:40:20 If-None-Match: "2822498463".
17:40:20 .
17:40:20
17:40:20 2010-09-17 17:40:20: (response.c.300) -- splitting Request-URI
17:40:20 2010-09-17 17:40:20: (response.c.301) Request-URI  :  /manager/html
17:40:20 2010-09-17 17:40:20: (response.c.302) URI-scheme   :  http
17:40:20 2010-09-17 17:40:20: (response.c.303) URI-authority:  127.0.0.1
17:40:20 2010-09-17 17:40:20: (response.c.304) URI-path     :  /manager/html
17:40:20 2010-09-17 17:40:20: (response.c.305) URI-query    :
17:40:20 2010-09-17 17:40:20: (response.c.300) -- splitting Request-URI
17:40:20 2010-09-17 17:40:20: (response.c.301) Request-URI  :  /cgi/infinity
17:40:20 2010-09-17 17:40:20: (response.c.302) URI-scheme   :  http
17:40:20 2010-09-17 17:40:20: (response.c.303) URI-authority:  127.0.0.1
17:40:20 2010-09-17 17:40:20: (response.c.304) URI-path     :  /cgi/infinity
17:40:20 2010-09-17 17:40:20: (response.c.305) URI-query    :
17:40:20 2010-09-17 17:40:20: (response.c.349) -- sanatising URI
17:40:20 2010-09-17 17:40:20: (response.c.350) URI-path     :  /cgi/infinity
17:40:20 2010-09-17 17:40:20: (mod_access.c.135) -- mod_access_uri_handler called
17:40:20 2010-09-17 17:40:20: ...
17:40:20 2010-09-17 17:40:20: magnet-secu.lua: gsub('/cgi/infinity','(/w00tw00t%.)','%1')
17:40:20 2010-09-17 17:40:20: magnet-secu.lua: gsub('/cgi/infinity','(UNION)%s','%1')
17:40:20 2010-09-17 17:40:20: ...
17:40:20 2010-09-17 17:40:20: (response.c.470) -- before doc_root
17:40:20 2010-09-17 17:40:20: (response.c.471) Doc-Root     : /home/www/doc
17:40:20 2010-09-17 17:40:20: (response.c.472) Rel-Path     : /cgi/infinity
17:40:20 2010-09-17 17:40:20: (response.c.473) Path         :
17:40:20 2010-09-17 17:40:20: (response.c.521) -- after doc_root
17:40:20 2010-09-17 17:40:20: (response.c.522) Doc-Root     : /home/www/doc
17:40:20 2010-09-17 17:40:20: (response.c.523) Rel-Path     : /cgi/infinity
17:40:20 2010-09-17 17:40:20: (response.c.524) Path         : /home/www/doc/cgi/infinity
17:40:20 2010-09-17 17:40:20: (response.c.541) -- logical -> physical
17:40:20 2010-09-17 17:40:20: (response.c.542) Doc-Root     : /home/www/doc
17:40:20 2010-09-17 17:40:20: (response.c.543) Rel-Path     : /cgi/infinity
17:40:20 2010-09-17 17:40:20: (response.c.544) Path         : /home/www/doc/cgi/infinity
17:40:20 2010-09-17 17:40:20: (response.c.561) -- handling physical path
17:40:20 2010-09-17 17:40:20: (response.c.562) Path         : /home/www/doc/cgi/infinity
17:40:20 2010-09-17 17:40:20: (response.c.569) -- file found
17:40:20 2010-09-17 17:40:20: (response.c.570) Path         : /home/www/doc/cgi/infinity
17:40:20 2010-09-17 17:40:20: (response.c.719) -- handling subrequest
17:40:20 2010-09-17 17:40:20: (response.c.720) Path         : /home/www/doc/cgi/infinity
17:40:20 2010-09-17 17:40:20: (mod_access.c.135) -- mod_access_uri_handler called
17:40:20 2010-09-17 17:40:20: (response.c.128) Response-Header:
17:40:20 HTTP/1.1 200 OK.
17:40:20 Last-Modified: Sun, 28 Dec 2003 20:15:00 GMT.
17:40:20 Content-Type: text/html.
17:40:20 Transfer-Encoding: chunked.
17:40:20 Date: Fri, 17 Sep 2010 15:40:20 GMT.
17:40:20 Server: Santos Al Helper.
17:40:20 .
17:40:20
17:40:20 127.0.0.1 127.0.0.1 - [17/Sep/2010:17:40:20 +0200] "GET /manager/html HTTP/1.1" 200 2780 "http://127.0.0.1/manager/html" "Lynx/2.8.5 (Compatible; ELinks)"
}}}
--]]--
res_rewrite = function(new_request, block)
    if block then block_ip(new_request) end
    -- lighty.header["Content-Type"] = "application/octet-stream"
    -- lighty.env["uri.query"] = uri_query .. (uri_query == "" and "" or "&") .. "q=" .. request_uri
    -- lighty.env["request.orig-uri"]  = request_uri
    -- lighty.env["uri.path"] = new_request
    -- lighty.env["physical.rel-path"] = new_request
    -- lighty.env["physical.path"] = doc_root .. new_request
    lighty.env["request.uri"] = new_request
    return lighty.RESTART_REQUEST
end

local cgi_infinity = "/cgi/infinity"

--[[-- format: each entry of trigger_patterns is a table of four entries:
selector, table-of-two-strings: lighty[index1][index2],
  given as a short-hand from above, like l_uri.
pattern, string: a Lua regex, possibly with captures.
replacement, string: the string replacing the pattern, used in the
  "reason" block message and rewriting-URI, possibly with captures.
function, table: first entry one of the res_* function names from above,
  mandatory, the rest being additional arguments.  NB: every res_*
  function gets the replacement string as its first argument, then come
  the additionals.  This allows rewrites to make use of captures.
--]]--
local trigger_patterns = {
    {l_uri, "(/w00tw00t%-test)", "%1",
        { res_block, DROP }},
    {l_uri, "(/w00tw00t%.)", "%1",
        { res_reflect, DROP }},
    {l_user_agent, "(dragostea mea pentru)", "%1",
        { res_block, DROP }},
    {l_uri, "(/[pP][hH][pP][mM][yY][aA][dD][mM][iI][nN])", "%1",
        { res_reflect, DROP }},
    {l_uri, "([aA][dD][mM][iI][nN].*[sS][cC][rR][Ii][pP][tT][sS])", "%1",
        { res_reflect, DROP }},
    {l_uri, "(/[sS][cC][rR][iI][pP][tT][sS]/[sS][eE][tT][uU][pP]%.[pP][hH][pP])", "%1",
        { res_reflect, DROP }},
    {l_uri, "^(.-/pp/anp%.php.*)$", cgi_infinity,
        {res_rewrite, DROP}},
    {l_uri, "^(.-/manager/anp%.php.*)$", cgi_infinity,
        {res_rewrite, DROP}},
    -- --[[--
    {l_uri, "^(.-/pp/html.*)$", cgi_infinity,
        {res_rewrite, DROP}},
    {l_uri, "^(.-/manager/html.*)$", cgi_infinity,
        {res_rewrite, DROP}},
    -- --]]--
    {l_uri, "(UNION)%s", "%1",
        { res_reflect, DROP }},
}

--[[--
unfortunately, Lua-5.1 has no "continue" statement, hence the "ex>0"
tests. this logic is purely convenient: if one entry has wrong types, it
will get logged, but the hunt goes on ...
--]]--
local function check_patterns()
    local ex = 1
    local trig_idx, trig_item
    local item_sel, item_pat, item_res, item_fun
    local t_item_sel, t_item_res, t_item_pat, t_item_fun
    local result, n_match
    for trig_idx, trig_item in ipairs(trigger_patterns) do
        ex = 1
        t_item_sel = type(trig_item)
        if t_item_sel ~= "table" then
            logg(0, "entry [" .. trig_idx .. "] must be table: " .. t_item_sel)
            ex = -1
        end
        if (ex > 0) then
            -- item_sel, item_pat, item_res, item_fun = false, false, false, false
            item_sel, item_pat, item_res, item_fun = unpack(trig_item)
            t_item_sel = type(item_sel)
            if (t_item_sel == "table") then
                item_sel = lighty[item_sel[1]][item_sel[2]] or ""
            else
                logg(0, "selector [" .. trig_idx .. "] must be table: " .. t_item_sel)
                ex = -1
            end
        end
        if (ex > 0) then
            t_item_res = type(item_pat) .. "/" .. type(item_res)
            if (t_item_res ~= "string/string") then
                logg(0, "both pattern/replacement of [" .. trig_idx .. "] must be string: " .. t_item_res)
                ex = -1
            end
        end
        if (ex > 0) then
            t_item_fun = type(item_fun)
            if (t_item_fun == "table") then
                result, n_match = gsub(item_sel, item_pat, item_res)
                if n_match > 0 then
                    logg(2, "gsub('"..item_sel.."','"..item_pat.."','"..item_res.."')")
                    t_item_fun = type(item_fun[1])
                    if (t_item_fun == "function") then
                        ex = item_fun[1](result, unpack(item_fun, 2))
                    else
                        logg(0, "result of [" .. trig_idx .. "] must be function: " .. t_item_fun)
                    end
                    break
                end
            else
                logg(0, "result [" .. trig_idx .. "] must be table: " .. t_item_fun)
            end
        end
    end
    return ex
end

ret_code = check_patterns()

-- fallthrough will put it back into the lighty request loop
-- that means we get the 304 handling for free. ;)

if (type(ret_code) == "number") then
    if not ((ret_code == lighty.RESTART_REQUEST) or (ret_code >= 100)) then ret_code = false end
else
    ret_code = false
end
if ret_code then
    return ret_code
else
    return
end
