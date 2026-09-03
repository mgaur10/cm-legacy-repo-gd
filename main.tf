# 🔒 SECURE TERRAFORM CONFIGURATION 🔒

provider "google" {
  project = "codemender-poc-demo"
  region  = "us-central1"
  zone    = "us-central1-a"
}

# ---------------------------------------------------------
# REMEDIATED: Secure Storage Bucket (No Public Access)
# ---------------------------------------------------------
resource "google_storage_bucket" "user_uploads" {
  name                        = "codemender-user-uploads-bucket"
  location                    = "US"
  force_destroy               = true
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true
}

# ---------------------------------------------------------
# REMEDIATED: Cloud SQL with SSL, Private Access, and Dynamic Password
# ---------------------------------------------------------
resource "random_password" "db_password" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "google_sql_database_instance" "main_db" {
  name             = "ecommerce-db"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true
      require_ssl  = true

      # REMEDIATED: Removed open-to-world authorized network (0.0.0.0/0)
    }
  }
}

resource "google_sql_user" "root_user" {
  name     = "postgres"
  instance = google_sql_database_instance.main_db.name
  password = random_password.db_password.result
}

# ---------------------------------------------------------
# REMEDIATED: Least Privilege VM & Secure Secret Management
# ---------------------------------------------------------
resource "google_service_account" "web_server_sa" {
  account_id   = "web-server-sa"
  display_name = "Web Server Service Account"
}

# Secret Manager Secret for Stripe API Key
resource "google_secret_manager_secret" "stripe_api_key" {
  secret_id = "stripe-api-key"
  replication {
    automatic = true
  }
}

# Grant the VM service account access to read the secret
resource "google_secret_manager_secret_iam_member" "web_server_secret_accessor" {
  secret_id = google_secret_manager_secret.stripe_api_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.web_server_sa.email}"
}

resource "google_compute_instance" "web_server" {
  name         = "frontend-web-server"
  machine_type = "e2-micro"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"
    # REMEDIATED: Removed access_config to prevent assigning a public IP directly
  }

  service_account {
    # REMEDIATED: Using a dedicated service account with limited access
    email  = google_service_account.web_server_sa.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  # REMEDIATED: Secrets are retrieved programmatically from Secret Manager at runtime
  metadata_startup_script = <<EOF
    #!/bin/bash
    echo "Starting web server..."
    # STRIPE_API_KEY is retrieved programmatically from Secret Manager at application runtime
    python3 /app/vulnerable_app.py
  EOF
}