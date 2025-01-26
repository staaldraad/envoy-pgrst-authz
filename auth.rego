package authz

default allow := false

allow if {
    is_service_role
}

allow if {
	not deny
}

is_service_role if {
    input.jwt.role == "service_role"
}

deny if {
    selects_id
}

deny if {
    selects_all
}

selects_id if {
  input.table == "apix"
  input.select[_] == "id"
}

selects_all if {
    input.table == "apix"
    input.select == null
}