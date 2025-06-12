variable "ami_id" {
  description = "AMI ID"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "vpc_id" {
  description = "VPC ID where the resources will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for DB subnet group"
  type        = list(string)
}


variable "db_password" {
  type = string
  sensitive = true
}

variable "public_key" {
  description = "SSH public key value"
  type        = string
}
