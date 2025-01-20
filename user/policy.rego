package policy

default allow = false

allow {
    input.user.roles[_] == "admin"
}