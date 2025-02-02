permit (
	principal,
	action,
	resource
) when {
    principal.role == "service_role"
};

permit (
	principal,
	action == Action::"SELECT",
	resource == Table::"apix"
) when {
    principal.role == "anon"
};

