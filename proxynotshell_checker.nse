local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Check for Microsoft Exchange servers potentially vulnerable to ProxyNotShell (CVE-2022-40140 & CVE-2022-41082).

References: 
https://www.gteltsc.vn/blog/warning-new-attack-campaign-utilized-a-new-0day-rce-vulnerability-on-microsoft-exchange-server-12715.html
https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/
https://doublepulsar.com/proxynotshell-the-story-of-the-claimed-zero-day-in-microsoft-exchange-5c63d963a9e9
]]


-- @usage
-- nmap --script proxynotshell_checker.nse -p443 <host> 

author = "Germán Fernández (@1ZRR4H)"
license = "GPLv3"
categories = {"default", "discovery", "safe"}
portrule = shortport.http

local function CheckVuln(host,port)
    payload = "/autodiscover/autodiscover.json?a@foo.var/owa/&Email=autodiscover/autodiscover.json?a@foo.var&Protocol=XYZ&FooProtocol=Powershell"
    local options = {header={}}
    options["header"]["User-Agent"] = 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0'
    response = http.get(host,port,payload,options)
    if (response.header['x-feserver'] ~= nil) then 
        return "*** Potentially Vulnerable to ProxyNotShell ***"
    else 
        return "Not Vulnerable."
    end
end

action = function(host, port)
    local options = {header={}}
    options["header"]["User-Agent"] = 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0'
    local resp = http.get(host,port,"/owa/",options)
    local response = stdnse.output_table()
    if (resp.status == 200) then
        response["Microsoft Exchange"] = CheckVuln(host,port)
    else 
        return "Apparently it is not a valid Microsoft Exchange server."
    end
    return response
end
