output "web1_public_ip" {
  value = aws_instance.web1.public_ip
}

output "web2_public_ip" {
  value = aws_instance.web2.public_ip
}


output "alb_dns_name" {
  value = aws_lb.app_lb.dns_name
}

output "rds_endpoint" {
  value = aws_db_instance.flask_db.address
}

output "rds_database" {
  value = aws_db_instance.flask_db.db_name
}
