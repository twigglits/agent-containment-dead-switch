# Phase 2 Hetzner Cloud: off-host controller + deletable egress chokepoint + firewalls.
# The dedicated (bare-metal) evaluation host is ordered via Hetzner Robot out-of-band (see robot.md)
# and joins the WireGuard mesh as a peer; this config does NOT manage its lifecycle.
# Hardened per Codex start-of-Phase-2 review (2026-09-13): chokepoint firewall, SSH restricted to an
# operator CIDR, pinned provider, WireGuard mesh so controller<->hostd traffic is ENCRYPTED and the
# dedicated host (which a `type=cloud` subnet cannot reach) connects over WireGuard.
terraform {
  required_version = ">= 1.6"
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "1.48.1" # pinned (was ~> 1.48)
    }
    cloudinit = {
      source  = "hashicorp/cloudinit"
      version = "2.3.5"
    }
  }
}

variable "hcloud_token" {
  type      = string
  sensitive = true
  # supply via TF_VAR_hcloud_token, sourced from the repo .env HETZNER_API_KEY
}
variable "ssh_pubkey" { type = string }
variable "operator_cidr" {
  type        = string
  description = "Operator IPv4 CIDR for SSH; mesh peers cannot SSH these nodes."
  validation {
    condition     = can(cidrnetmask(var.operator_cidr)) && try(tonumber(split("/", var.operator_cidr)[1]) > 0, false)
    error_message = "operator_cidr must be an IPv4 CIDR narrower than /0."
  }
}
variable "controller_location" {
  type    = string
  default = "fsn1" # co-located with the dedicated eval host (FSN1) for a tight WireGuard mesh
}
variable "chokepoint_location" {
  type    = string
  default = "fsn1"
}
# Chokepoint hosts the pre-staged, model-pinned inference backend. The validated fleet is x86_64.
variable "chokepoint_server_type" {
  type    = string
  default = "cpx31" # x86, 8GB (cax/arm unavailable); hosts pinned inference
}
# An immutable image/snapshot ID, independently verified by the operator. A mutable OS label
# (ubuntu-24.04) is not a build pin. The image must contain no keys, tokens, peers or workload state.
variable "cloud_image_id" {
  type = number
  validation {
    condition     = var.cloud_image_id > 0 && floor(var.cloud_image_id) == var.cloud_image_id
    error_message = "Supply a positive, immutable x86_64 image/snapshot ID for the CPX fleet."
  }
}

locals {
  controller_wgip = "10.20.0.1"
  chokepoint_wgip = "10.20.0.2"
}

provider "hcloud" {
  token = var.hcloud_token
}

resource "hcloud_ssh_key" "ops" {
  name       = "deadswitch-ops"
  public_key = var.ssh_pubkey
}

# WireGuard uses public endpoints; no Cloud-only network/implicit lateral management path.

# ---- Controller: the independent trusted node. Operator SSH (restricted) + hostd over WireGuard only.
resource "hcloud_firewall" "controller" {
  name = "deadswitch-controller"
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = [var.operator_cidr] # operator only (Codex: was 0.0.0.0/0)
  }
  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "51820"               # WireGuard
    source_ips = ["0.0.0.0/0", "::/0"] # WG is authenticated by key; peers roam
  }
  # NOTE: controller :7100 is bound to the WireGuard interface only (see cloud-init), so it is NOT
  # exposed on the public NIC and needs no public firewall rule. hostd reaches it at 10.20.0.1:7100.
}

# ---- Egress chokepoint: only the eval-host exact-action proxy connects here. The host never forwards
# raw guest traffic. Off-host deletion removes the workload's sole mediated inference destination.
resource "hcloud_firewall" "chokepoint" {
  name = "deadswitch-chokepoint"
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = [var.operator_cidr] # operator only (was: no firewall at all)
  }
  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "51820"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

data "cloudinit_config" "node" {
  for_each      = toset(["controller", "chokepoint"])
  gzip          = false
  base64_encode = false
  part {
    content_type = "text/cloud-config"
    content = yamlencode({
      package_update = true
      packages       = ["wireguard", "nftables", "python3", "curl"]
      write_files = [
        {
          path        = "/usr/local/sbin/ds-bootstrap-node"
          permissions = "0700"
          content     = file("${path.module}/../../hetzner/bootstrap-node.sh")
        },
        {
          path        = "/usr/local/sbin/chokepoint-forward.sh"
          permissions = "0700"
          content     = file("${path.module}/../../hetzner/chokepoint-forward.sh")
        }
      ]
      # Only public role/CIDR configuration in user-data. Keys are generated locally; no peers or
      # inference service start here. A recreated node is quarantined behind a FRESH transport key.
      runcmd = [["/usr/local/sbin/ds-bootstrap-node", each.key, var.operator_cidr]]
    })
  }
}

resource "hcloud_server" "controller" {
  name         = "deadswitch-controller"
  image        = tostring(var.cloud_image_id)
  server_type  = "cpx11" # x86 (cax/arm unavailable on this account); controller binary is static musl
  location     = var.controller_location
  ssh_keys     = [hcloud_ssh_key.ops.id]
  firewall_ids = [hcloud_firewall.controller.id]
  user_data    = data.cloudinit_config.node["controller"].rendered
  labels       = { role = "controller" }
}

resource "hcloud_server" "chokepoint" {
  name         = "deadswitch-chokepoint"
  image        = tostring(var.cloud_image_id)
  server_type  = var.chokepoint_server_type # ≥8GB: hosts the pinned inference backend
  location     = var.chokepoint_location
  ssh_keys     = [hcloud_ssh_key.ops.id]
  firewall_ids = [hcloud_firewall.chokepoint.id]
  user_data    = data.cloudinit_config.node["chokepoint"].rendered
  labels       = { role = "chokepoint" }
}

output "controller_ip" { value = hcloud_server.controller.ipv4_address }
output "chokepoint_ip" { value = hcloud_server.chokepoint.ipv4_address }
output "chokepoint_id" { value = hcloud_server.chokepoint.id } # pin in the operator allocation record; do not resolve by name at kill time
output "controller_wgip" { value = local.controller_wgip }
output "chokepoint_wgip" { value = local.chokepoint_wgip }
output "next_steps" {
  value = "Read each node public key over verified SSH; use configure-wireguard.sh on all three nodes with operator-pinned public keys/endpoints. No second Terraform apply configures peers. Provision the Linux eval-host backend and independent actuator/observer before commissioning (see the Phase 2 review)."
}
