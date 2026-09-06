// Dev/infra scenario - only SRE agents may run destructive operations.
// Principal: Agent (.role, .trust_score 0-100). Resource: Tool. Action: callTool.

permit (
    principal,
    action == Action::"callTool",
    resource
)
when {
    (resource == Tool::"delete_database" || resource == Tool::"deploy") &&
    principal.role == "sre" &&
    principal.trust_score >= 75
};

permit (
    principal,
    action == Action::"callTool",
    resource
)
when {
    resource == Tool::"list_files" || resource == Tool::"read_logs"
};

forbid (
    principal,
    action == Action::"callTool",
    resource
)
when {
    (resource == Tool::"delete_database" || resource == Tool::"deploy") &&
    principal.role != "sre"
};
