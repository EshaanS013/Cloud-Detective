output "vpc_id" { value = aws_vpc.this.id }
output "public_subnet_ids" { value = values(aws_subnet.public)[*].id }
output "database_subnet_ids" { value = values(aws_subnet.database)[*].id }
output "alb_sg_id" { value = aws_security_group.alb.id }
output "app_sg_id" { value = aws_security_group.app.id }
output "database_sg_id" { value = aws_security_group.database.id }
