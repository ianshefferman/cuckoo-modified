// Copyright (C) 2010-2014 Cuckoo Foundation.
// This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
// See the file 'docs/LICENSE' for copying permission.

// The contents of this file are Yara rules processed by procmemory.py processing
// module. Add your signatures here.
rule DyreServerlist
{
    meta:
        author = "KillerInstinct"
        description = "Configuration element for Dyre serverlist"

    strings:
        $re1 = /\<serverlist\>.*\<\/serverlist\>/s

    condition:
        $re1
}

rule DyreInjectsList
{
    meta:
        author = "KillerInstinct"
        description = "Configuration element for Dyre web injects"

    strings:
        $re1 = /\<litem\>.*\<\/litem\>/s

    condition:
        $re1
}

rule DridexCfgNodeList
{
    meta:
        author = "KillerInstinct"
        description = "Configuration element for Dridex node list"

    strings:
        $re1 = /\<node\>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\<\/node\>/s

    condition:
        $re1
}

rule DridexCfgKeylog
{
    meta:
        author = "KillerInstinct"
        description = "Configuration element for Dridex keylogger"

    strings:
        $re1 = /\<latest.*\keylog=.*\/\>/s

    condition:
        $re1
}

