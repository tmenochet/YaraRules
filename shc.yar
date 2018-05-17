rule shc
{
    meta:
        author = "Timothee MENOCHET (@synetis)"
        description = "Detect encrypted file produced by SHc (http://www.datsi.fi.upm.es/~frosal/sources/shc.html)"
        note = "Encryption can be reversed using UnSHc (https://github.com/yanncam/UnSHc)" 
    strings:
        $s_main_fprintf_1 = "%s%s%s: %s\n" ascii wide nocase
        $s_main_fprintf_2 = "<null>" ascii wide nocase
        $s_chkenv_sprintf_1 = "x%lx" ascii wide nocase
        $s_chkenv_sprintf_2 = "=%lu %d" ascii wide nocase
        $s_chkenv_sscanf_1 = "%lu %d%c" ascii wide nocase
    condition:
        all of them
}
