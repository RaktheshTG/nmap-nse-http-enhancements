-- Cyber Security course (Fall Semester 2026-2027), School of Computer Science and Engineering (SCOPE), VIT Chennai
-- Assignment: enhancement of Nmap's http-title.nse
-- Author: Rakthesh
-- Guided by: Dr. T. Subbulakshmi, Professor, SCOPE, VIT Chennai
-- Based on: http-title.nse (author: Diman Todorov)
-- License: same as Nmap (https://nmap.org/book/man-legal.html), which is based on the GNU GPL with additional terms
description = [[
Scans an open HTTP port by sending a standard GET request to 
extract the web page title and HTTP response status code.
]]

author = "Rakthesh"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local http = require("http")
local shortport = require("shortport")

portrule = shortport.http

action = function(host, port)
    -- Send standard HTTP GET request
    local response = http.get(host, port, "/")

    if not response or not response.status then
        return "[-] Error: No response received from target."
    end

    local output = "\n--- HTTP Page Title & Status Scan ---\n"
    output = output .. "  [+] Response Status: HTTP " .. response.status .. "\n"

    -- Extract page title from HTML body if present
    if response.body then
        local title = string.match(response.body, "<[tT][iI][tT][lL][eE]>(.-)</[tT][iI][tT][lL][eE]>")
        if title then
            output = output .. "  [+] Web Page Title : " .. title
        else
            output = output .. "  [-] Web Page Title : <No title tag found>"
        end
    end

    return output
end
