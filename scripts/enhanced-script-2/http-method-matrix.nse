local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Performs empirical HTTP method profiling across target web endpoints.

Unlike default auditing scripts (such as http-methods, which audits the Allow header and flags 'risky' methods), http-method-matrix performs pure transport discovery without pass/fail compliance heuristics or vulnerability judgments.

Default Nmap scripts rely on an OPTIONS request to read the Allow header; if OPTIONS is disabled, blocked, or stripped by reverse proxies/WAFs, default scripts fail to discover supported functionality. In contrast, http-method-matrix actively transmits discrete, lightweight probes for each standard HTTP verb (GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS, TRACE) directly to the specified path (defaulting to /). It measures the actual empirical response from the server:
  - HTTP Verb / Method tested
  - HTTP Response Status Code (e.g., 200, 204, 401, 403, 405, 501)
  - HTTP Reason Phrase (e.g., OK, Method Not Allowed, Forbidden)
  - Response Content-Length
  - Response Content-Type

Additionally, if the OPTIONS response returns an Allow header, it is extracted and displayed alongside the empirical matrix to highlight any divergence between advertised methods and actual endpoint behavior.
]]

---
-- @usage
-- nmap --script http-method-matrix -p 80 <target>
-- nmap --script http-method-matrix --script-args http-method-matrix.path=/api/v1 -p 80,443 <target>
-- nmap --script http-method-matrix --script-args http-method-matrix.methods="GET,POST,PUT,DELETE" -p 80 <target>
--
-- @output
-- PORT      STATE SERVICE
-- 80/tcp    open  http
-- | http-method-matrix:
-- |   Target Path: /
-- |   Advertised via OPTIONS (Allow): GET, HEAD, OPTIONS
-- |   
-- |   METHOD   STATUS REASON                   CONTENT-LENGTH   CONTENT-TYPE
-- |   ------   ------ ------                   --------------   ------------
-- |   GET      200    OK                       1024             text/html
-- |   HEAD     200    OK                       1024             text/html
-- |   POST     405    Method Not Allowed       154              text/html
-- |   PUT      403    Forbidden                0                -
-- |   DELETE   403    Forbidden                0                -
-- |   PATCH    405    Method Not Allowed       154              text/html
-- |   OPTIONS  200    OK                       0                -
-- |_  TRACE    501    Not Implemented          0                -
--
-- @args http-method-matrix.path The target path on the web server to test. Defaults to "/".
-- @args http-method-matrix.methods Comma-separated list of HTTP methods to probe.
--                                  Defaults to "GET,HEAD,POST,PUT,DELETE,PATCH,OPTIONS,TRACE".

author = "Antigravity"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local DEFAULT_METHODS = {
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "DELETE",
  "PATCH",
  "OPTIONS",
  "TRACE"
}

-- Mapping of standard HTTP status codes to reason phrases
local STATUS_PHRASES = {
  [100] = "Continue",
  [101] = "Switching Protocols",
  [200] = "OK",
  [201] = "Created",
  [202] = "Accepted",
  [203] = "Non-Authoritative Information",
  [204] = "No Content",
  [205] = "Reset Content",
  [206] = "Partial Content",
  [300] = "Multiple Choices",
  [301] = "Moved Permanently",
  [302] = "Found",
  [303] = "See Other",
  [304] = "Not Modified",
  [307] = "Temporary Redirect",
  [308] = "Permanent Redirect",
  [400] = "Bad Request",
  [401] = "Unauthorized",
  [402] = "Payment Required",
  [403] = "Forbidden",
  [404] = "Not Found",
  [405] = "Method Not Allowed",
  [406] = "Not Acceptable",
  [407] = "Proxy Authentication Required",
  [408] = "Request Timeout",
  [409] = "Conflict",
  [410] = "Gone",
  [411] = "Length Required",
  [412] = "Precondition Failed",
  [413] = "Payload Too Large",
  [414] = "URI Too Long",
  [415] = "Unsupported Media Type",
  [416] = "Range Not Satisfiable",
  [417] = "Expectation Failed",
  [422] = "Unprocessable Entity",
  [426] = "Upgrade Required",
  [429] = "Too Many Requests",
  [500] = "Internal Server Error",
  [501] = "Not Implemented",
  [502] = "Bad Gateway",
  [503] = "Service Unavailable",
  [504] = "Gateway Timeout",
  [505] = "HTTP Version Not Supported"
}

action = function(host, port)
  -- 1. Parse target path (defaulting to "/")
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path")
            or stdnse.get_script_args("http-method-matrix.path")
            or stdnse.get_script_args("path")
            or "/"

  if not path:match("^/") then
    path = "/" .. path
  end

  -- 2. Determine methods to probe
  local methods_arg = stdnse.get_script_args(SCRIPT_NAME .. ".methods")
                   or stdnse.get_script_args("http-method-matrix.methods")
                   or stdnse.get_script_args("methods")

  local methods = {}
  if methods_arg then
    for m in methods_arg:gmatch("[^,%s]+") do
      table.insert(methods, m:upper())
    end
  end
  if #methods == 0 then
    methods = DEFAULT_METHODS
  end

  -- Lightweight probe options:
  -- redirect_ok = false ensures we observe the exact status code returned for that verb
  -- no_cache = true avoids receiving cached results
  local req_opts = {
    redirect_ok = false,
    no_cache = true
  }

  local matrix_results = {}
  local allow_header = nil
  local successful_probes = 0

  for _, method in ipairs(methods) do
    local resp = http.generic_request(host, port, method, path, req_opts)
    if resp and resp.status then
      successful_probes = successful_probes + 1

      -- Extract Reason Phrase:
      -- Prefer reason phrase in raw status-line, fallback to standard map
      local reason = nil
      if resp["status-line"] then
        reason = resp["status-line"]:match("^HTTP/%d+%.%d+ +%d+ +([^\r\n]*)")
      end
      if not reason or reason == "" then
        reason = STATUS_PHRASES[resp.status] or "-"
      end

      -- Extract Content-Length
      local length = "-"
      if resp.header and resp.header["content-length"] then
        length = tostring(resp.header["content-length"])
      elseif resp.body then
        length = tostring(#resp.body)
      end

      -- Extract Content-Type
      local content_type = "-"
      if resp.header and resp.header["content-type"] then
        content_type = resp.header["content-type"]
      end

      -- Check for Allow: header on OPTIONS probe (or 405 probe)
      if method == "OPTIONS" and resp.header and resp.header["allow"] then
        allow_header = resp.header["allow"]
      elseif not allow_header and resp.status == 405 and resp.header and resp.header["allow"] then
        allow_header = resp.header["allow"]
      end

      table.insert(matrix_results, {
        method = method,
        status = resp.status,
        reason = reason,
        length = length,
        type = content_type
      })
    else
      -- Network timeout or connection drop for this specific probe
      table.insert(matrix_results, {
        method = method,
        status = "-",
        reason = "No response / Timeout",
        length = "-",
        type = "-"
      })
    end
  end

  if successful_probes == 0 then
    stdnse.debug1("No HTTP responses received for any method probe against %s:%s%s", host.targetname or host.ip, port.number, path)
    return nil
  end

  -- 3. Build structured XML table
  local xml_out = stdnse.output_table()
  xml_out["Target Path"] = path
  if allow_header then
    xml_out["Advertised via OPTIONS (Allow)"] = allow_header
  end

  local xml_matrix = stdnse.output_table()
  for _, r in ipairs(matrix_results) do
    local entry = stdnse.output_table()
    entry["Status Code"] = r.status
    entry["Reason Phrase"] = r.reason
    entry["Content-Length"] = r.length
    entry["Content-Type"] = r.type
    xml_matrix[r.method] = entry
  end
  xml_out["Method Matrix"] = xml_matrix

  -- 4. Build clean human-readable CLI table
  local text_lines = {}
  table.insert(text_lines, string.format("Target Path: %s", path))
  if allow_header then
    table.insert(text_lines, string.format("Advertised via OPTIONS (Allow): %s", allow_header))
  else
    table.insert(text_lines, "Advertised via OPTIONS (Allow): (none advertised)")
  end
  table.insert(text_lines, "")
  table.insert(text_lines, string.format("%-8s %-6s %-24s %-16s %s", "METHOD", "STATUS", "REASON", "CONTENT-LENGTH", "CONTENT-TYPE"))
  table.insert(text_lines, string.format("%-8s %-6s %-24s %-16s %s", "------", "------", "------", "--------------", "------------"))

  for _, r in ipairs(matrix_results) do
    local status_str = tostring(r.status)
    table.insert(text_lines, string.format("%-8s %-6s %-24s %-16s %s",
      r.method,
      status_str,
      r.reason,
      r.length,
      r.type
    ))
  end

  return xml_out, stdnse.format_output(true, text_lines)
end
