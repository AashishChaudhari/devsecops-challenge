import os
import multiprocessing

# Server socket
bind = "0.0.0.0:5000"

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Restart workers after this many requests (prevents memory leaks)
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = "-"   # stdout
errorlog = "-"    # stderr
loglevel = "info"

# Process naming
proc_name = "devsecops-app"

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190
