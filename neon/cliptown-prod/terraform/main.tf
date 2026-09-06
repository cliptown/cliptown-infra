terraform {
  required_providers { neon = { source = "kislerdm/neon", version = "~> 0.6" } }
}
provider "neon" {}  # NEON_API_KEY from the environment (ores-sops), never in git

resource "neon_project" "prod" {
  name      = "cliptown-prod"
  region_id = "aws-us-east-1"
}
resource "neon_role" "app"  { project_id = neon_project.prod.id; branch_id = neon_project.prod.default_branch_id; name = "cliptown_app" }
resource "neon_role" "auth" { project_id = neon_project.prod.id; branch_id = neon_project.prod.default_branch_id; name = "cliptown_auth" }
resource "neon_database" "canonical" { project_id = neon_project.prod.id; branch_id = neon_project.prod.default_branch_id; name = "canonical"; owner_name = neon_role.app.name }
resource "neon_database" "auth"      { project_id = neon_project.prod.id; branch_id = neon_project.prod.default_branch_id; name = "auth";      owner_name = neon_role.auth.name }
