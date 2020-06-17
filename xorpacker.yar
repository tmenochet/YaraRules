rule XorPacker
{
    meta:
        author = "Timothee MENOCHET (@_tmenochet)"
        description = "Detect PE file produced by XorPacker (https://github.com/tmenochet/XorPacker)"
    strings:
        $s_go = "go.buildid" ascii nocase
        $s_bf_xor = "main.bf_xor" ascii nocase
    condition:
        uint16(0) == 0x5a4d and
        all of them
}
