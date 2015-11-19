rule bit9_bit9_macho_launchctl_load
{
    meta:
        author = "ddorsey@bit9.com"
        date = "9.30.2015"
        description = "See if the file has launchctl in it"
    strings:
        $header0 = { cf fa ed fe }
        $header1 = { ce fa ed fe }
        $header2 = { ca fe ba be }
        $string1 = "launchctl load"
		$launch0 = "/Library/LaunchDaemons" nocase
        $launch1 = "/Library/LaunchAgents" nocase
    condition:
        ($header0 at 0 or $header1 at 0 or $header2 at 0) and $string1 and any of ($launch*)
}


rule bit9_macho_usr_bin
{
    meta:
        author = "ddorsey@bit9.com"
        date = "9.30.2015"
        description = "See if the file has /usr/bin/ in it"
    strings:
        $header0 = { cf fa ed fe }
        $header1 = { ce fa ed fe }
        $header2 = { ca fe ba be }
        $string1 = "/usr/bin/"
    condition:
        ($header0 at 0 or $header1 at 0 or $header2 at 0) and $string1
}


rule bit9_macho_google_extensions
{
    meta:
        author = "ddorsey@bit9.com"
        date = "9.30.2015"
        description = "See if the file could be messing with Google Chrome Extensions"
    strings:
        $header0 = { cf fa ed fe }
        $header1 = { ce fa ed fe }
        $header2 = { ca fe ba be }
        $string1 = "/Google/Chrome/Default/Extensions/"
    condition:
        ($header0 at 0 or $header1 at 0 or $header2 at 0) and $string1
}

rule bit9_macho_safari_extensions
{
    meta:
        author = "ddorsey@bit9.com"
        date = "9.30.2015"
        description = "See if the file could be messing with Safari Extensions"
    strings:
        $header0 = { cf fa ed fe }
        $header1 = { ce fa ed fe }
        $header2 = { ca fe ba be }
        $string1 = "Safari/Extensions"
    condition:
        ($header0 at 0 or $header1 at 0 or $header2 at 0) and $string1
}


rule bit9_macho_firefox
{
    meta:
        author = "ddorsey@bit9.com"
        date = "9.30.2015"
        description = "See if the file could be messing with Firefox"
    strings:
        $header0 = { cf fa ed fe }
        $header1 = { ce fa ed fe }
        $header2 = { ca fe ba be }
        $string1 = "/Library/Application Support/Firefox/"
    condition:
        ($header0 at 0 or $header1 at 0 or $header2 at 0) and $string1
}

rule bit9_macho_keychain
{
    meta:
        author = "ddorsey@bit9.com"
        date = "9.30.2015"
        description = "See if the file could be messing with the Keychain"
    strings:
        $header0 = { cf fa ed fe }
        $header1 = { ce fa ed fe }
        $header2 = { ca fe ba be }
        $string1 = "Library/Keychains/login.keychain"
    condition:
        ($header0 at 0 or $header1 at 0 or $header2 at 0) and $string1
}


