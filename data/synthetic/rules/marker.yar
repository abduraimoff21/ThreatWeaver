rule TW_Synthetic_Marker
{
    meta:
        description = "Synthetic example rule for the ThreatWeaver test harness"
    strings:
        $text = "THREATWEAVER-SYNTHETIC-MARKER" ascii
        $hex  = { 54 57 2D 54 45 53 54 }
    condition:
        $text or $hex
}
