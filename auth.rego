package authz

default allow := false

allow if {
	not deny
}

deny if {
    selects_id
}

deny if {
    selects_all
}

selects_id if {
  input.select[_] == "id"
}

selects_all if {
    input.select == null
}