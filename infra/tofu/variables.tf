# Coldline - Task 4.10
# File: infra/tofu/variables.tf
# Component: OpenTofu input variables
# Purpose: Declare the name prefix every sandbox resource is named from.
# Interacts With: infra/tofu/main.tf, poe tofu-plan, poe tofu-apply, poe tofu-destroy, poe infra-diff, poe verify
# Sprint/Task: Sprint 4 - Project 4 / Task 4.10
# Concepts: One declaration, several copies side by side, named by a prefix
# Tools: OpenTofu

# Supplied and not student-editable. `poe tofu-plan`, `poe tofu-apply` and `poe tofu-destroy`
# pass `coldline-sandbox`; `poe verify` passes a prefix of its own, so its run never touches
# your sandbox. The stack's own resources are named from `coldline`, which this variable
# refuses, so no prefix can name the stack's own resources.

variable "name_prefix" {
  description = "The prefix every declared resource is named from, followed by a hyphen."
  type        = string
  default     = "coldline-sandbox"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*[a-z0-9]$", var.name_prefix)) && length(var.name_prefix) <= 40 && var.name_prefix != "coldline"
    error_message = "The prefix is lowercase letters, digits and hyphens, at most 40 characters, and never the stack's own `coldline`."
  }
}
