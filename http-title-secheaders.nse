description = [[
Extends http-title by reporting the HTTP status code, the page title,
and which common security headers the server sends or omits.
]]

author = "Rakthesh"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local http = require("http")
local shortport = require("shortport")

portrule = shortport.http

-- Security headers we audit (Nmap lowercases header names)
local headers_to_check = {
  "x-frame-options",
  "x-content-type-options",
  "content-security-policy"
}

action = function(host, port)
  local response = http.get(host, port, "/")

  if not response or not response.status then
    return "[-] Error: No response received from target."
  end

  local output = "\n--- HTTP Title, Status & Security Header Scan ---\n"
  output = output .. "  [+] Response Status: HTTP " .. response.status .. "\n"

  -- Extract and clean the page title
  local title = nil
  if response.body then
    title = string.match(response.body, "<[tT][iI][tT][lL][eE]>(.-)</[tT][iI][tT][lL][eE]>")
  end
  if title then
    title = title:gsub("^%s*(.-)%s*$", "%1")  -- trim whitespace
    output = output .. "  [+] Web Page Title : " .. title .. "\n"
  else
    output = output .. "  [-] Web Page Title : <No title tag found>\n"
  end

  -- Audit security headers
  output = output .. "  Security Headers:\n"
  for _, name in ipairs(headers_to_check) do
    local value = response.header[name]
    if value then
      output = output .. "    [+] " .. name .. ": " .. tostring(value) .. "\n"
    else
      output = output .. "    [-] " .. name .. ": MISSING\n"
    end
  end

  return output
end
