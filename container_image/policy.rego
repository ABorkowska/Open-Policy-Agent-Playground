package kubernetes

# The policy  checks if the container object's `"image"` field does not start with "hooli.com/".

deny[msg] {
    some j      # "some" keyword declares local variables
	input.request.kind.kind == "Pod"

	image :=  input.request.object.spec.containers[j].image
    name  :=  input.request.object.spec.containers[j].name
	not startswith(image, "hooli.com/")
	msg := sprintf("Image '%v' comes '%v' from untrusted registry", [image,name])
}
# The policy allows if the container object's `"image"` starts with "hooli.com/". field

allow {
    some j
	input.request.kind.kind == "Pod"

	image :=  input.request.object.spec.containers[j].image
    name  :=  input.request.object.spec.containers[j].name
	startswith(image, "hooli.com/")
}