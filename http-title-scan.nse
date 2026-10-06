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
