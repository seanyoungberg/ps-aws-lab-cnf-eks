variable "cluster_name" {
  default = "k8s"
  type = string
}

variable "vpc_name" {
  default = "k8s-vpc1"
  type = string
}

variable "kubeconfig_output_path" {
  default = "~/.kube/config"
  type = string
}

variable "region" {
  default = "us-west-2"
  type = string
}

variable "safe_ips" {
  default = [
    "8.47.64.2/32",         #hq
    "34.99.77.241/32",      #prisma nl central
    "34.99.77.242/32",      #prisma nl central
    "54.241.37.235/32",     #prisma us west
    "83.242.74.253/32",     #amsterdam-gw
    "84.207.227.0/28",      #amsterdam-gw
    "84.207.230.24/29",     #amsterdam lab
    "134.238.0.0/16",       #pan /16
    "213.39.97.34/32",      #amsterdam-gp
    "0.0.0.0/0"             #everywhere for QwikLabs :)
  ]
  type = list
}

variable "owner" {
  type = string
}

variable "key_pair" {
  type = string
}


variable "management-vpc" { default = {} }
variable "management-vpc-subnets" { default = [] }
variable "management-vpc-route-tables" { default = [] }
variable "management-vpc-security-groups" { default = [] }
variable "management-vpc-routes" { default = [] }
variable "panorama" { default = {} }

variable "prefix-name-tag" {}
variable "global_tags" {}