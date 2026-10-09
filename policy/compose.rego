package main

import rego.v1

deny contains msg if {
    some name, service in input.services
    service.privileged == true
    msg := sprintf("Servicio %s: privileged=true no permitido", [name])
}
