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
    not is_own_id
}

deny if {
    selects_all
    not is_own_id
}

selects_id if {
  input.table == "apix"
  input.select[_] == "id"
}

selects_all if {
    input.table == "apix"
    input.select == null
}

is_own_id if {
    own_id := input.jwt.id
    input.filters.id == sprintf("eq.%s",[own_id])
}