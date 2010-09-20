-- /usr/local/etc/lighttpd/magnet-secu.lua _date: 20100920-0219_
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
-- fix for your document root
local doc_root = lighty.env["physical.doc-root"] or "/home/www/doc"
-- where this modules "mod_status" counters root
local module_stats = "magnet.secu"
-- IPs in this table will never get blocked
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
local s_match = string.match
local s_gsub = string.gsub
local s_find = string.find

local function count_up(counter)
    local cnt = false
    assert((type(counter)=="string"), "count_up: counter must be string!")
    if lighty.status then
        cnt = lighty.status[counter]
        if cnt then
            cnt = cnt + 1
        else
            cnt = 0
        end
        lighty.status[counter] = cnt
    end
    return cnt
end

-- "nil", "number", "string", "boolean", "table", "function", "thread", "userdata"

local function except_ip(ip)
    local excepted = false
    local mess
    local idx, ip_p, t_ip_p
    for idx, ip_p in ipairs(ip_exceptions) do
        t_ip_p = type(ip_p)
        if t_ip_p == "string" then
            excepted = s_match(ip, ip_p)
            if excepted then break end
        else
            logg(0, "ip_exceptions[" .. idx .. "]: must be string: " .. t_ip_p)
        end
    end
    mess = (excepted and "excepted: " or "blocked: ") .. remote_ip
    -- note that strings count as true in Lua
    return excepted, mess
end

local function block_ip(originator, reason)
    local ex = true
    local excepted, mess = except_ip(remote_ip)
    mess = mess .. ": " .. originator .. ": (" .. reason .. ") -- "
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

-- keys: "code", "permanence", "request"
local template_redirect = [[
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>$code$ Moved $permanence$</title>
</head><body>
<h1>Moved $permanence$</h1>
<p>The document has moved <a href="$request$">here</a>.</p>
</body></html>
]]
local function make_redirect(template, code, request)
    local ex
    local permanence = ((code == "301") and "Permanently") or "Temporarily"
    assert((type(template)=="string"), "template must be string!")
    assert((type(request)=="string"), "request must be string!")
    ex = s_gsub(template, "%$(%w+)%$", {
        code=code, permanence=permanence, request=request
    })
    if s_find(template, ex, 1, true) then
        logg(0, "make_redirect: no substitions made!")
        ex = false
    end
    return ex
end
-- send the attacker back to where it came from, let him attack his own
-- site.
res_reflect = function(text, block, code, headers, mk_body)
    local content
    local new_request
    local permanence
    local iam = "res_reflect"
    count_up(module_stats .. "." .. iam)
    assert((s_match(code, "^30[12]$")), "redirect code must be 301 or 302!")
    permanence = ((code == "301") and "Permanently") or "Temporarily"
    -- why doesn't this work?
    -- local host, host_port = s_match(uri_authority, "^(.+)(%:.*)?$")
    local host, host_port = s_match(uri_authority, "^(.-)(:.*)$")
    if host then
        host = remote_ip .. host_port
    else
        host = remote_ip
    end
    if block then block_ip(iam, text) end
    new_request = uri_scheme .. "://" .. host .. request_uri
    if mk_body then
        content = make_redirect(template_redirect, code, new_request)
        if content then
            lighty.content = { content }
        else
            logg(0, iam .. ": make_redirect() text problem")
        end
    end
    lighty.header["Location"] = new_request
    lighty.header["Status"] = code .. " Moved " .. permanence
    if type(headers) == "table" then
        for key, val in pairs(headers) do
            lighty.header[key] = val
        end
    else
        logg(0, iam .. ": arg 'headers' must be table!")
    end
    -- return 302 301
    return tonumber(code)
end
-- block the attacker with a configurable http code.
res_block = function(text, block, code)
    local iam = "res_block"
    count_up(module_stats .. "." .. iam)
    if block then block_ip(iam, text) end
    lighty.header["Content-Type"] = "text/plain"
    lighty.content = { "blocked" }
    -- return 405
    return code
end
-- send the attacker elsewhere eg. using a CGI.
res_rewrite = function(new_request, block)
    iam = "res_rewrite"
    count_up(module_stats .. "." .. iam)
    if block then block_ip(iam, new_request) end
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
local redir_headers = {
    -- ["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate, post-check=0, pre-check=0",
    ["Cache-Control"] = "max-age=0, no-cache, no-store",
    ["Connection"] = "close",
    -- ["Connection"] = "Keep-Alive",
    ["Content-Type"] = "text/html; charset=iso-8859-1",
    -- ["Content-Type"] = "text/html; charset=UTF-8",
    ["Expires"] = "Thu, 16 Sep 2010 17:33:08 GMT",
    ["Keep-Alive"] = "timeout=20, max=968",
    ["Pragma"] = "no-cache",
    ["Server"] = "Apache-kakka",
    ["X-Backend-Server"] = "popl-web02",
    -- ["X-Cache-Info"] = "cached",
    ["X-Cache-Info"] = "deferred",
    -- ["X-Cache-Info"] = "not cacheable; response is 302 without expiry time",
    ["X-Powered-By"] = "PHP/5.2.9",
}

--[[-- format: each entry of trigger_patterns is a table of four entries:
selector, table-of-two-strings: lighty[index1][index2],
  given as a short-hand from above, like l_uri.
pattern, string: a Lua regex, possibly with captures.
replacement, string: the string replacing the pattern, used in the
  "reason" block message and rewriting-URI, possibly with captures.
function, table: first entry one of the res_* function names from above,
  mandatory, the rest being additional arguments.  NB: every res_*
  function gets the replacement string as its first argument, then come
  the additionals.  This allows rewrites to make use of captures.  The
  second entry should be a boolean indicating whether to drop further
  queries from the client.
--]]--
local trigger_patterns = {
    {l_uri, "(/w00tw00t%-test)", "%1",
        { res_block, DROP, 405 }},
    {l_uri, "(/w00tw00t%.)", "%1",
        { res_reflect, DROP, "301", redir_headers, true }},
    {l_user_agent, "(dragostea mea pentru)", "%1",
        { res_block, DROP, 405 }},
    {l_uri, "(/[pP][hH][pP][mM][yY][aA][dD][mM][iI][nN])", "%1",
        { res_reflect, DROP, "301", redir_headers, true }},
    {l_uri, "([aA][dD][mM][iI][nN].*[sS][cC][rR][Ii][pP][tT][sS])", "%1",
        { res_reflect, DROP, "301", redir_headers, true }},
    {l_uri, "(/[sS][cC][rR][iI][pP][tT][sS]/[sS][eE][tT][uU][pP]%.[pP][hH][pP])", "%1",
        { res_reflect, DROP, "301", redir_headers, true }},
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
        { res_reflect, DROP, "301", redir_headers, true }},
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
                result, n_match = s_gsub(item_sel, item_pat, item_res)
                if n_match > 0 then
                    logg(2, "s_gsub('"..item_sel.."','"..item_pat.."','"..item_res.."')")
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
count_up(module_stats)

-- fallthrough will put it back into the lighty request loop
-- that means we get the 304 handling for free. ;)

if (type(ret_code) == "number") then
    if not ((ret_code == lighty.RESTART_REQUEST) or (ret_code >= 100)) then ret_code = false end
else
    ret_code = false
end
if ret_code then
    count_up(module_stats .. "." .. tostring(ret_code))
    return ret_code
else
    return
end
