variable "region" {
  default = "us-east-1"
}

variable "web_acl_arn" {
  description = "WAF Web ACL ARN"
}

variable "log_group" {
  description = "CloudWatch log group for WAF logs"
}

variable "sns_topic_arn" {
  description = "SNS topic ARN (leave empty to create new)"
  default     = ""
}

variable "schedule_expression" {
  description = "EventBridge Scheduler A cron expression in SGT timezone — fires the trigger Lambda (default: 8AM SGT daily)"
  default     = "cron(0 8 * * ? *)"
}

variable "healthcheck_schedule_expression" {
  description = "EventBridge Scheduler B cron expression in SGT timezone — fires the healthcheck Lambda. Must be at least (runner Lambda timeout / 60) minutes after schedule_expression."
  default     = "cron(15 8 * * ? *)"
}

variable "healthcheck_hang_threshold_minutes" {
  description = "A run marker with status='started' and age above this value is considered hung by healthcheck (must be < gap between A and B schedulers)"
  default     = 12
}

variable "schedule_enabled" {
  description = "Enable/disable both EventBridge Schedulers (A: trigger, B: healthcheck)"
  default     = true
}

variable "abuseipdb_api_key" {
  description = "AbuseIPDB API key for IP reputation enrichment (free: 1000 checks/day)"
  default     = ""
  sensitive   = true
}

variable "gateway_policy_mode" {
  description = "AgentCore Gateway policy engine mode: ENFORCE (Cedar decisions are binding) or LOG_ONLY (observe only)"
  default     = "ENFORCE"
  validation {
    condition     = contains(["ENFORCE", "LOG_ONLY"], var.gateway_policy_mode)
    error_message = "gateway_policy_mode must be ENFORCE or LOG_ONLY."
  }
}

variable "allow_waf_write" {
  description = "Hard switch for the tools Lambda: when false, update_web_acl_rules refuses any non-dry-run call regardless of what an agent requests"
  default     = false
}

variable "schedule_timezone" {
  description = "IANA timezone used by both EventBridge Schedulers and shown in the report footer"
  default     = "Asia/Singapore"
}

variable "agent_models" {
  description = "Bedrock model/inference-profile ID per agent"
  type        = map(string)
  default = {
    supervisor = "us.anthropic.claude-sonnet-4-6"
    analyzer   = "us.anthropic.claude-opus-4-6-v1"
    validator  = "us.anthropic.claude-opus-4-6-v1"
    executor   = "us.anthropic.claude-opus-4-6-v1"
  }
}

variable "detection_thresholds" {
  description = "Overrides for tools-Lambda detection thresholds (subset of keys in lambda/tools_handler.py DEFAULT_THRESHOLDS), e.g. { fp_attacker_block_ratio = 0.8 }"
  type        = map(number)
  default     = {}
}

variable "agent_env_overrides" {
  description = "Extra environment variables merged into every AgentCore runtime (e.g. FP_SIGNAL_MAX_IPS, REPUTATION_MAX_IPS, DEEP_INVESTIGATION_PCT, CONFIDENCE_THRESHOLD)"
  type        = map(string)
  default     = {}
}
