import "pe"

rule nsis
{
    meta:
        author = "Timothee MENOCHET (@synetis)"
        description = "Detect PE produced by Nullsoft Scriptable Install System (https://sourceforge.net/projects/nsis/)"
    condition:
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".ndata"
        )
}
