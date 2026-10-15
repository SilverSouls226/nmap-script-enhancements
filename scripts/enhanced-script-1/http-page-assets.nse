local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

description = [[
Discovers, parses, and inventories client-side web page assets and hyperlinks referenced within an HTTP response.

Unlike auditing scripts, this script performs pure passive discovery and extraction without evaluating compliance or security vulnerabilities. Unlike default Nmap scripts (such as http-title, which only extracts the page title, or http-enum, which guesses paths from a static dictionary), http-page-assets inspects the actual DOM structure of the fetched HTML document. It extracts and categorizes:
  - Internal Hyperlinks: Relative and same-domain links in <a href="...">
  - External Domains / Endpoints: Third-party absolute URLs in <a href="...">
  - JavaScript Resources: Scripts linked via <script src="...">
  - CSS Stylesheets: Linked stylesheets via <link rel="stylesheet" href="...">
  - Media / Image Assets: Embedded images via <img src="...">

Extracted assets are normalized, relative paths are resolved against the base request path, duplicates are pruned, and results are returned as a structured output table.
]]

---
-- @usage
-- nmap --script http-page-assets -p 80 <target>
-- nmap --script http-page-assets --script-args http-page-assets.path=/index.html -p 80,443 <target>
--
-- @output
-- PORT      STATE SERVICE
-- 80/tcp    open  http
-- | http-page-assets:
-- |   Internal Hyperlinks:
-- |     /about
-- |     /contact.html
-- |     /dashboard
-- |     /faq.html
-- |     /pricing/plans
-- |     /search?query=security&sort=desc
-- |   External Domains / Endpoints:
-- |     http://cdn.jsdelivr.net/npm/bootstrap@5/dist/js/bootstrap.bundle.min.js
-- |     https://api.external-service.org/v1/health
-- |     https://github.com/nmap/nmap
-- |   JavaScript Resources:
-- |     /scripts/utils.js
-- |     /static/js/app.js
-- |     https://code.jquery.com/jquery-3.6.0.min.js
-- |   CSS Stylesheets:
-- |     /static/css/bootstrap.min.css
-- |     /styles/theme.css
-- |     https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap
-- |_  Media / Image Assets:
-- |     /assets/banner.jpg
-- |     /static/images/logo.png
-- |     https://images.unsplash.com/photo-example.jpg
--
-- @args http-page-assets.path The path to request and parse on the web server. Default: "/".

author = "Antigravity"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

--- Helper function to generate a case-insensitive Lua pattern for a string.
-- @param str The string to convert.
-- @return The case-insensitive Lua pattern.
local function ci_pat(str)
  local p = ""
  for i = 1, #str do
    local c = str:sub(i, i)
    p = p .. "[" .. c:lower() .. c:upper() .. "]"
  end
  return p
end

--- Helper function to extract an attribute value from an HTML tag attribute string.
-- Handles double quotes, single quotes, and unquoted attribute values.
-- @param attrs Tag attribute string.
-- @param name Attribute name (case-insensitive).
-- @return The extracted attribute value string, or nil if not found.
local function extract_attr(attrs, name)
  if not attrs or not name then return nil end
  local p_name = ci_pat(name)
  -- 1. Double-quoted: attr="..."
  local val = attrs:match("%f[%a]" .. p_name .. "%s*=%s*\"([^\"]*)\"")
  if not val then
    -- 2. Single-quoted: attr='...'
    val = attrs:match("%f[%a]" .. p_name .. "%s*=%s*'([^']*)'")
  end
  if not val then
    -- 3. Unquoted: attr=value
    val = attrs:match("%f[%a]" .. p_name .. "%s*=%s*([^%s>/\"']+)")
  end
  return val
end

action = function(host, port)
  -- Retrieve target path from script arguments, default to "/"
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path")
            or stdnse.get_script_args("http-page-assets.path")
            or stdnse.get_script_args("path")
            or "/"

  -- Ensure path has a leading slash
  if not path:match("^/") then
    path = "/" .. path
  end

  -- Send HTTP GET request
  local resp = http.get(host, port, path)

  -- Error handling: No response or invalid status
  if not resp or not resp.status then
    stdnse.debug1("No response received from %s:%s for path %s", host.targetname or host.ip, port.number, path)
    return nil
  end

  -- Edge Case 1: Non-200 responses
  if resp.status ~= 200 then
    stdnse.debug1("HTTP GET %s returned status %d (expected 200 OK)", path, resp.status)
    if stdnse.get_script_args(SCRIPT_NAME .. ".path") or stdnse.get_script_args("http-page-assets.path") or stdnse.get_script_args("path") then
      return string.format("HTTP GET %s returned status %d (expected 200 OK)", path, resp.status)
    end
    return nil
  end

  -- Edge Case 2: Empty body
  if not resp.body or #resp.body == 0 then
    stdnse.debug1("HTTP GET %s returned an empty response body", path)
    return nil
  end

  -- Edge Case 3: Non-HTML content-types
  local content_type = resp.header and (resp.header["content-type"] or resp.header["Content-Type"])
  if content_type then
    local ct_lower = content_type:lower()
    if not (ct_lower:find("html", 1, true) or ct_lower:find("xhtml", 1, true) or ct_lower:find("xml", 1, true)) then
      stdnse.debug1("Skipping non-HTML Content-Type: %s on %s", content_type, path)
      if nmap.verbosity() > 1 then
        return string.format("Non-HTML Content-Type (%s) on %s", content_type, path)
      end
      return nil
    end
  end

  -- Determine target hostnames and IP for same-domain detection
  local local_hosts = {}
  if host.ip then local_hosts[host.ip:lower()] = true end
  if host.targetname then
    local tn = host.targetname:lower()
    local_hosts[tn] = true
    if tn:match("^www%.") then
      local_hosts[tn:gsub("^www%.", "")] = true
    else
      local_hosts["www." .. tn] = true
    end
  end
  if host.name then
    local_hosts[host.name:lower()] = true
  end
  -- Support loopback aliases
  if host.ip == "127.0.0.1" or host.ip == "::1" or (host.targetname and host.targetname:lower() == "localhost") then
    local_hosts["127.0.0.1"] = true
    local_hosts["::1"] = true
    local_hosts["localhost"] = true
  end

  local function is_same_host(hostname)
    if not hostname or hostname == "" then
      return true
    end
    return local_hosts[hostname:lower()] == true
  end

  -- Determine protocol scheme (http vs https)
  local proto = (port.version and port.version.service_tunnel == "ssl")
                or (port.service == "https")
                or (port.number == 443)
                or (port.version and port.version.name == "ssl/http")
                and "https" or "http"

  local host_hdr = host.targetname or host.name or host.ip
  local base_url = string.format("%s://%s:%d%s", proto, host_hdr, port.number, path)

  -- Strip HTML comments to avoid parsing commented-out dummy assets
  local clean_html = resp.body:gsub("<!%-%-.-%-%->", "")

  -- Edge Case 4: Base href resolution (<base href="...">)
  local base_tag_attrs = clean_html:match("<%s*" .. ci_pat("base") .. "[%s/]+([^>]+)>")
  if base_tag_attrs then
    local custom_base = extract_attr(base_tag_attrs, "href")
    if custom_base and custom_base ~= "" then
      base_url = url.absolute(base_url, custom_base)
    end
  end

  -- URL resolution helper:
  -- Distinguishes root-relative (/path) vs directory-relative (path) paths,
  -- resolves against base_url, strips DOM fragments, and classifies into internal vs external.
  local function resolve_link(raw_link)
    if not raw_link or type(raw_link) ~= "string" then
      return nil, false
    end

    -- Trim whitespace
    local s = raw_link:match("^%s*(.-)%s*$")
    if not s or s == "" or s:sub(1, 1) == "#" then
      return nil, false
    end

    -- Ignore non-HTTP client pseudo-schemes
    local scheme = s:match("^([%a][%w+.-]*):")
    if scheme then
      local sc = scheme:lower()
      if sc == "javascript" or sc == "mailto" or sc == "tel" or sc == "data" then
        return nil, false
      end
      if sc == "http" or sc == "https" then
        local clean = s:gsub("#.*$", "")
        local parsed = url.parse(clean)
        if parsed and is_same_host(parsed.host) then
          local p = parsed.path or "/"
          if parsed.query and parsed.query ~= "" then
            p = p .. "?" .. parsed.query
          end
          return p, true
        else
          return clean, false
        end
      else
        return s:gsub("#.*$", ""), false
      end
    end

    -- Handle protocol-relative URLs (e.g., //cdn.example.com/asset.js)
    if s:sub(1, 2) == "//" then
      local clean = proto .. ":" .. s:gsub("#.*$", "")
      local parsed = url.parse(clean)
      if parsed and is_same_host(parsed.host) then
        local p = parsed.path or "/"
        if parsed.query and parsed.query ~= "" then
          p = p .. "?" .. parsed.query
        end
        return p, true
      else
        return clean, false
      end
    end

    -- Handle relative paths (/path vs path vs ../path) resolved against base_url
    local clean = s:gsub("#.*$", "")
    local abs = url.absolute(base_url, clean)
    local parsed = url.parse(abs)
    if parsed then
      local p = parsed.path or "/"
      if parsed.query and parsed.query ~= "" then
        p = p .. "?" .. parsed.query
      end
      return p, true
    else
      return clean, true
    end
  end

  -- Categorized deduplication buckets
  local seen = {
    internal = {},
    external = {},
    scripts = {},
    stylesheets = {},
    media = {}
  }
  local lists = {
    internal = {},
    external = {},
    scripts = {},
    stylesheets = {},
    media = {}
  }

  local function add_item(category, item)
    if item and item ~= "" and not seen[category][item] then
      seen[category][item] = true
      table.insert(lists[category], item)
    end
  end

  -- 1. Extract Hyperlinks: <a ... href="...">
  -- Categorized into Internal Hyperlinks (relative or same-domain) and External Domains / Endpoints
  for attrs in clean_html:gmatch("<%s*" .. ci_pat("a") .. "[%s/]+([^>]+)>") do
    local href = extract_attr(attrs, "href")
    if href then
      local resolved, is_internal = resolve_link(href)
      if resolved then
        if is_internal then
          add_item("internal", resolved)
        else
          add_item("external", resolved)
        end
      end
    end
  end

  -- 2. Extract JavaScript Resources: <script ... src="...">
  for attrs in clean_html:gmatch("<%s*" .. ci_pat("script") .. "[%s/]+([^>]+)>") do
    local src = extract_attr(attrs, "src")
    if src then
      local resolved, _ = resolve_link(src)
      if resolved then
        add_item("scripts", resolved)
      end
    end
  end

  -- 3. Extract Stylesheets: <link ... href="..."> where rel matches stylesheet
  for attrs in clean_html:gmatch("<%s*" .. ci_pat("link") .. "[%s/]+([^>]+)>") do
    local rel = extract_attr(attrs, "rel")
    if rel and rel:lower():find("stylesheet", 1, true) then
      local href = extract_attr(attrs, "href")
      if href then
        local resolved, _ = resolve_link(href)
        if resolved then
          add_item("stylesheets", resolved)
        end
      end
    end
  end

  -- 4. Extract Media Assets: <img ... src="...">
  for attrs in clean_html:gmatch("<%s*" .. ci_pat("img") .. "[%s/]+([^>]+)>") do
    local src = extract_attr(attrs, "src")
    if src then
      local resolved, _ = resolve_link(src)
      if resolved then
        add_item("media", resolved)
      end
    end
  end

  -- Sort lists for consistent, deterministic reporting
  table.sort(lists.internal)
  table.sort(lists.external)
  table.sort(lists.scripts)
  table.sort(lists.stylesheets)
  table.sort(lists.media)

  -- Build structured output table
  local output = stdnse.output_table()
  local total_assets = 0

  if #lists.internal > 0 then
    output["Internal Hyperlinks"] = lists.internal
    total_assets = total_assets + #lists.internal
  end

  if #lists.external > 0 then
    output["External Domains / Endpoints"] = lists.external
    total_assets = total_assets + #lists.external
  end

  if #lists.scripts > 0 then
    output["JavaScript Resources"] = lists.scripts
    total_assets = total_assets + #lists.scripts
  end

  if #lists.stylesheets > 0 then
    output["CSS Stylesheets"] = lists.stylesheets
    total_assets = total_assets + #lists.stylesheets
  end

  if #lists.media > 0 then
    output["Media / Image Assets"] = lists.media
    total_assets = total_assets + #lists.media
  end

  -- Edge Case: No assets detected
  if total_assets == 0 then
    if nmap.verbosity() > 0 then
      return string.format("No page assets or hyperlinks detected on %s", path)
    end
    return nil
  end

  return output
end
