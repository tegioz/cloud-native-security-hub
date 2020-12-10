package kubernetes.admission

deny[msg] {
    registry := "docker.io/"
    input.request.kind.kind == "Pod"
    some i
    image := input.request.object.spec.containers[i].image
    not startswith(image, registry)
    msg := sprintf("image '%v' comes from untrusted registry", [image])
}
