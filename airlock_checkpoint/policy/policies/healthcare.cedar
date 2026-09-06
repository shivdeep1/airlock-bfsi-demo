// Healthcare scenario - only clinicians may export or email patient records.
// Principal: Agent (.role, .trust_score 0-100). Resource: Tool. Action: callTool.

permit (
    principal,
    action == Action::"callTool",
    resource
)
when {
    (resource == Tool::"export_patient_records" || resource == Tool::"email_records") &&
    principal.role == "clinician" &&
    principal.trust_score >= 75
};

permit (
    principal,
    action == Action::"callTool",
    resource
)
when {
    resource == Tool::"read_chart" || resource == Tool::"schedule_appointment"
};

forbid (
    principal,
    action == Action::"callTool",
    resource
)
when {
    (resource == Tool::"export_patient_records" || resource == Tool::"email_records") &&
    principal.role != "clinician"
};
