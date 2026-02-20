rule Synthetic_Intake_Note : synthetic text
{
    meta:
        description = "Identifies a marked synthetic intake note"

    strings:
        $header_lf   = "LAB-INTAKE/1\n"
        $header_crlf = "LAB-INTAKE/1\r\n"
        $status      = "status=training-only"

    condition:
        ($header_lf at 0 or $header_crlf at 0) and $status
}

rule Synthetic_Review_Trace : synthetic text
{
    meta:
        description = "Identifies a synthetic review trace with corroborating fields"

    strings:
        $marker         = "LAB-REVIEW/1"
        $field_queue    = "queue=fixture-review"
        $field_decision = "decision=manual-check"
        $field_owner    = "owner=training-desk"

    condition:
        $marker and 2 of ($field_*)
}

rule Synthetic_Archive_Tag : synthetic binary
{
    meta:
        description = "Identifies a versioned synthetic binary envelope with an early tag"

    strings:
        $tag = "training-archive"

    condition:
        uint32be(0) == 0x594C4142 and  // ASCII YLAB
        uint16be(4) == 0x0100 and     // version 1, flags 0
        $tag in (8..31)
}

rule Synthetic_Practice_Receipt : synthetic text
{
    meta:
        description = "Identifies a synthetic receipt with a fixed opening record"

    strings:
        $record = /LAB-RECEIPT\/1\r?\nreceipt_id=R[0-9]{4}\r?\nmode=practice(\r?\n|$)/

    condition:
        $record at 0
}
