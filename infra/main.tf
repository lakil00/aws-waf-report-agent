terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.54" }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { "auto-delete" = "none" }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  sns_topic_arn = var.sns_topic_arn != "" ? var.sns_topic_arn : aws_sns_topic.waf_report.arn

  agents = { for name, model in var.agent_models : name => { model = model } }

  gateway_url = "https://${aws_bedrockagentcore_gateway.waf_tools.gateway_id}.gateway.bedrock-agentcore.${var.region}.amazonaws.com/mcp"
}

# ============================================================
# SNS Topic
# ============================================================
resource "aws_sns_topic" "waf_report" {
  name = "aws-waf-report-agent-topic"
}

# ============================================================
# ECR Repositories (one per agent)
# ============================================================
resource "aws_ecr_repository" "agents" {
  for_each             = local.agents
  name                 = "waf-report-${each.key}"
  image_tag_mutability = "MUTABLE"
  force_delete         = true
}

# ============================================================
# Docker Build + Push (all 4 agents)
# ============================================================
resource "null_resource" "docker_push" {
  for_each = local.agents

  triggers = {
    handler_hash = filesha256("${path.module}/../agents/${each.key}/handler.py")
    docker_hash  = filesha256("${path.module}/../agents/Dockerfile")
    req_hash     = filesha256("${path.module}/../agents/requirements.txt")
  }

  provisioner "local-exec" {
    working_dir = "${path.module}/../agents"
    command     = <<-EOT
      aws ecr get-login-password --region ${var.region} | docker login --username AWS --password-stdin ${aws_ecr_repository.agents[each.key].repository_url}
      docker buildx build --platform linux/arm64 --build-arg AGENT_NAME=${each.key} -t ${aws_ecr_repository.agents[each.key].repository_url}:latest --push .
    EOT
  }

  depends_on = [aws_ecr_repository.agents]
}

# ============================================================
# Lambda — WAF Tools (shared, invoked by Gateway)
# ============================================================
data "archive_file" "lambda_code" {
  type        = "zip"
  source_file = "${path.module}/../lambda/tools_handler.py"
  output_path = "${path.module}/lambda_tools.zip"
}

resource "aws_iam_role" "lambda" {
  name = "waf-report-tools-lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_permissions" {
  name = "waf-tools-permissions"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["wafv2:GetWebACL", "wafv2:UpdateWebACL"]
        Resource = [var.web_acl_arn, "${var.web_acl_arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:StartQuery", "logs:GetQueryResults", "logs:StopQuery", "logs:GetLogEvents", "logs:FilterLogEvents"]
        Resource = ["arn:aws:logs:${var.region}:${local.account_id}:log-group:${var.log_group}:*"]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:DescribeLogGroups"]
        Resource = ["arn:aws:logs:${var.region}:${local.account_id}:log-group:*"]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket", "s3:PutObject", "s3:DeleteObject", "s3:CopyObject"]
        Resource = [aws_s3_bucket.findings.arn, "${aws_s3_bucket.findings.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["cloudwatch:GetMetricStatistics"]
        Resource = ["*"]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/lambda/*"]
      },
    ]
  })
}

resource "aws_lambda_function" "tools" {
  function_name    = "waf-report-tools"
  role             = aws_iam_role.lambda.arn
  handler          = "tools_handler.handler"
  runtime          = "python3.11"
  timeout          = 120
  filename         = data.archive_file.lambda_code.output_path
  source_code_hash = data.archive_file.lambda_code.output_base64sha256

  environment {
    variables = {
      ABUSEIPDB_API_KEY = var.abuseipdb_api_key
      FINDINGS_BUCKET   = aws_s3_bucket.findings.id
      WAF_WRITE_ENABLED = tostring(var.allow_waf_write)
      REGION            = var.region
      DEFAULT_TIMEZONE  = var.schedule_timezone
      WAF_THRESHOLDS    = jsonencode(var.detection_thresholds)
    }
  }
}

resource "aws_lambda_permission" "gateway_invoke" {
  statement_id  = "AllowAgentCoreGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.tools.function_name
  principal     = "bedrock-agentcore.amazonaws.com"
}

# ============================================================
# AgentCore Gateway (shared — single Lambda routes by _tool)
# ============================================================
resource "aws_iam_role" "gateway" {
  name = "waf-report-gateway"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock-agentcore.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "gateway_lambda" {
  name = "gateway-permissions"
  role = aws_iam_role.gateway.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = [aws_lambda_function.tools.arn]
      },
      {
        Sid    = "PolicyEngine"
        Effect = "Allow"
        Action = [
          "bedrock-agentcore:GetPolicyEngine",
          "bedrock-agentcore:EvaluatePolicy",
          "bedrock-agentcore:CheckAuthorizePermissions",
          "bedrock-agentcore:AuthorizeAction",
          "bedrock-agentcore:PartiallyAuthorizeActions",
        ]
        Resource = [
          "arn:aws:bedrock-agentcore:${var.region}:${local.account_id}:policy-engine/*",
          "arn:aws:bedrock-agentcore:${var.region}:${local.account_id}:/policy-engines/*",
          "arn:aws:bedrock-agentcore:${var.region}:${local.account_id}:gateway/*",
        ]
      },
    ]
  })
}

resource "aws_bedrockagentcore_gateway" "waf_tools" {
  name            = "waf-report-tools"
  role_arn        = aws_iam_role.gateway.arn
  protocol_type   = "MCP"
  authorizer_type = "AWS_IAM"
  exception_level = "DEBUG"

  policy_engine_configuration {
    arn  = aws_bedrockagentcore_policy_engine.waf_guard.policy_engine_arn
    mode = var.gateway_policy_mode
  }
}

resource "aws_s3_bucket" "agent_code" {
  bucket        = "waf-report-agent-code-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket" "findings" {
  bucket        = "waf-report-agent-findings-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_object" "tool_schemas" {
  bucket       = aws_s3_bucket.agent_code.id
  key          = "tool_schemas.json"
  source       = "${path.module}/tool_schemas.json"
  content_type = "application/json"
  etag         = filemd5("${path.module}/tool_schemas.json")
}

resource "aws_bedrockagentcore_gateway_target" "tools" {
  name               = "waf-tools-lambda"
  gateway_identifier = aws_bedrockagentcore_gateway.waf_tools.gateway_id

  credential_provider_configuration {
    gateway_iam_role {}
  }

  target_configuration {
    mcp {
      lambda {
        lambda_arn = aws_lambda_function.tools.arn
        tool_schema {
          s3 {
            uri = "s3://${aws_s3_bucket.agent_code.id}/${aws_s3_object.tool_schemas.key}"
          }
        }
      }
    }
  }

  lifecycle {
    replace_triggered_by = [aws_s3_object.tool_schemas.etag]
  }
}

# ============================================================
# Cedar Policy Engine (per-agent least-privilege tool access)
# ============================================================
resource "aws_bedrockagentcore_policy_engine" "waf_guard" {
  name = "waf_report_policy_engine"
}

locals {
  cedar_vars = {
    gateway_arn = aws_bedrockagentcore_gateway.waf_tools.gateway_arn
    target_name = aws_bedrockagentcore_gateway_target.tools.name
  }
  cedar_policies = {
    analyzer         = "policies/analyzer.cedar.tftpl"
    validator        = "policies/validator.cedar.tftpl"
    executor         = "policies/executor.cedar.tftpl"
    executor_dry_run = "policies/executor_dry_run.cedar.tftpl"
    supervisor       = "policies/supervisor.cedar.tftpl"
  }
}

resource "aws_bedrockagentcore_policy" "cedar" {
  for_each         = local.cedar_policies
  name             = each.key
  policy_engine_id = aws_bedrockagentcore_policy_engine.waf_guard.policy_engine_id
  # The conditional forbid (context.input.dry_run == false) is flagged "Overly Restrictive" by the
  # static validator even though it only applies when the condition holds; exempt that one policy.
  validation_mode = each.key == "executor_dry_run" ? "IGNORE_ALL_FINDINGS" : "FAIL_ON_ANY_FINDINGS"

  definition {
    cedar {
      statement = templatefile("${path.module}/${each.value}", merge(local.cedar_vars, {
        # IAM-authorized gateways expose the caller as AgentCore::IamEntity (no principal tags);
        # match the runtime role by its assumed-role ARN (session name is not part of the id).
        principal_id = "arn:aws:sts::${local.account_id}:assumed-role/waf-report-${replace(each.key, "executor_dry_run", "executor")}-runtime"
      }))
    }
  }
}

# ============================================================
# AgentCore Memory
# ============================================================
resource "aws_bedrockagentcore_memory" "waf_findings" {
  name                  = "waf_report_memory"
  description           = "Retains WAF findings across executions for trend detection"
  event_expiry_duration = 30
}

resource "aws_bedrockagentcore_memory_strategy" "semantic" {
  memory_id  = aws_bedrockagentcore_memory.waf_findings.id
  name       = "FindingsExtractor"
  type       = "SEMANTIC"
  namespaces = ["/findings/{actorId}/"]
}

resource "aws_bedrockagentcore_memory_strategy" "episodic" {
  memory_id  = aws_bedrockagentcore_memory.waf_findings.id
  name       = "ExecutionEvents"
  type       = "EPISODIC"
  namespaces = ["/events/{actorId}/{sessionId}/"]
}

# ============================================================
# IAM Roles — per-agent (least privilege)
# ============================================================

# Supervisor: invoke other runtimes + bedrock
resource "aws_iam_role" "runtime_supervisor" {
  name = "waf-report-supervisor-runtime"
  tags = { agent_role = "supervisor" }
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock-agentcore.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "supervisor_permissions" {
  name = "supervisor-permissions"
  role = aws_iam_role.runtime_supervisor.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = ["*"]
      },
      {
        Effect   = "Allow"
        Action   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
        Resource = [aws_ecr_repository.agents["supervisor"].arn]
      },
      {
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = ["*"]
      },
      {
        Effect   = "Allow"
        Action   = ["bedrock-agentcore:InvokeAgentRuntime"]
        Resource = ["arn:aws:bedrock-agentcore:${var.region}:${local.account_id}:runtime/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket", "s3:PutObject", "s3:DeleteObject"]
        Resource = [aws_s3_bucket.findings.arn, "${aws_s3_bucket.findings.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [local.sns_topic_arn]
      },
      {
        Sid      = "GatewayInvoke"
        Effect   = "Allow"
        Action   = ["bedrock-agentcore:InvokeGateway"]
        Resource = [aws_bedrockagentcore_gateway.waf_tools.gateway_arn]
      },
    ]
  })
}

# Sub-agents: bedrock + gateway (analyzer, executor) or bedrock only (validator)
resource "aws_iam_role" "runtime_subagent" {
  for_each = toset(["analyzer", "validator", "executor"])
  name     = "waf-report-${each.key}-runtime"
  tags     = { agent_role = each.key }
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock-agentcore.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "subagent_permissions" {
  for_each = toset(["analyzer", "validator", "executor"])
  name     = "${each.key}-permissions"
  role     = aws_iam_role.runtime_subagent[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = ["*"]
      },
      {
        Effect   = "Allow"
        Action   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
        Resource = [aws_ecr_repository.agents[each.key].arn]
      },
      {
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = ["*"]
      },
      {
        Sid      = "GatewayInvoke"
        Effect   = "Allow"
        Action   = ["bedrock-agentcore:InvokeGateway"]
        Resource = [aws_bedrockagentcore_gateway.waf_tools.gateway_arn]
      },
      {
        Sid    = "MemoryOperations"
        Effect = "Allow"
        Action = [
          "bedrock-agentcore:CreateEvent",
          "bedrock-agentcore:GetEvent",
          "bedrock-agentcore:ListEvents",
          "bedrock-agentcore:RetrieveMemoryRecords",
          "bedrock-agentcore:ListMemoryRecords",
          "bedrock-agentcore:StartMemoryExtractionJob",
          "bedrock-agentcore:ListMemoryExtractionJobs",
        ]
        Resource = [aws_bedrockagentcore_memory.waf_findings.arn]
      },
    ]
  })
}

# ============================================================
# AgentCore Runtimes (4)
# ============================================================
resource "aws_bedrockagentcore_agent_runtime" "supervisor" {
  agent_runtime_name = "waf_supervisor"
  role_arn           = aws_iam_role.runtime_supervisor.arn

  agent_runtime_artifact {
    container_configuration {
      container_uri = "${aws_ecr_repository.agents["supervisor"].repository_url}:latest"
    }
  }

  network_configuration {
    network_mode = "PUBLIC"
  }

  environment_variables = merge({
    MODEL_ID              = local.agents["supervisor"].model
    REGION                = var.region
    WEB_ACL_ARN           = var.web_acl_arn
    LOG_GROUP             = var.log_group
    SNS_TOPIC_ARN         = local.sns_topic_arn
    FINDINGS_BUCKET       = aws_s3_bucket.findings.id
    GATEWAY_URL           = local.gateway_url
    ANALYZER_RUNTIME_ARN  = aws_bedrockagentcore_agent_runtime.analyzer.agent_runtime_arn
    VALIDATOR_RUNTIME_ARN = aws_bedrockagentcore_agent_runtime.validator.agent_runtime_arn
    EXECUTOR_RUNTIME_ARN  = aws_bedrockagentcore_agent_runtime.executor.agent_runtime_arn
    SCHEDULE_EXPRESSION   = var.schedule_expression
    SCHEDULE_TIMEZONE     = var.schedule_timezone
    DEPLOY_VERSION        = filesha256("${path.module}/../agents/supervisor/handler.py")
  }, var.agent_env_overrides)

  depends_on = [null_resource.docker_push["supervisor"]]
}

resource "aws_bedrockagentcore_agent_runtime" "analyzer" {
  agent_runtime_name = "waf_analyzer"
  role_arn           = aws_iam_role.runtime_subagent["analyzer"].arn

  agent_runtime_artifact {
    container_configuration {
      container_uri = "${aws_ecr_repository.agents["analyzer"].repository_url}:latest"
    }
  }

  network_configuration {
    network_mode = "PUBLIC"
  }

  environment_variables = merge({
    MODEL_ID       = local.agents["analyzer"].model
    REGION         = var.region
    LOG_GROUP      = var.log_group
    WEB_ACL_ARN    = var.web_acl_arn
    GATEWAY_URL    = local.gateway_url
    MEMORY_ID      = aws_bedrockagentcore_memory.waf_findings.id
    DEPLOY_VERSION = filesha256("${path.module}/../agents/analyzer/handler.py")
  }, var.agent_env_overrides)

  depends_on = [null_resource.docker_push["analyzer"]]
}

resource "aws_bedrockagentcore_agent_runtime" "validator" {
  agent_runtime_name = "waf_validator"
  role_arn           = aws_iam_role.runtime_subagent["validator"].arn

  agent_runtime_artifact {
    container_configuration {
      container_uri = "${aws_ecr_repository.agents["validator"].repository_url}:latest"
    }
  }

  network_configuration {
    network_mode = "PUBLIC"
  }

  environment_variables = merge({
    MODEL_ID             = local.agents["validator"].model
    REGION               = var.region
    LOG_GROUP            = var.log_group
    WEB_ACL_ARN          = var.web_acl_arn
    CONFIDENCE_THRESHOLD = "0.7"
    GATEWAY_URL          = local.gateway_url
    DEPLOY_VERSION       = filesha256("${path.module}/../agents/validator/handler.py")
  }, var.agent_env_overrides)

  depends_on = [null_resource.docker_push["validator"]]
}


resource "aws_bedrockagentcore_agent_runtime" "executor" {
  agent_runtime_name = "waf_executor"
  role_arn           = aws_iam_role.runtime_subagent["executor"].arn

  agent_runtime_artifact {
    container_configuration {
      container_uri = "${aws_ecr_repository.agents["executor"].repository_url}:latest"
    }
  }

  network_configuration {
    network_mode = "PUBLIC"
  }

  environment_variables = merge({
    MODEL_ID       = local.agents["executor"].model
    REGION         = var.region
    WEB_ACL_ARN    = var.web_acl_arn
    GATEWAY_URL    = local.gateway_url
    DEPLOY_VERSION = filesha256("${path.module}/../agents/executor/handler.py")
  }, var.agent_env_overrides)

  depends_on = [null_resource.docker_push["executor"]]
}

# ============================================================
# EventBridge Schedulers + 3 Lambdas (trigger + runner + healthcheck)
# ------------------------------------------------------------
# Fire-and-forget from EventBridge; every retry knob is 0 except
# healthcheck's boto3 client (idempotent read-only work).
# ============================================================

# ---------- archive_files ----------
data "archive_file" "trigger_lambda" {
  type        = "zip"
  source_file = "${path.module}/../lambda/trigger_handler.py"
  output_path = "${path.module}/trigger_lambda.zip"
}

data "archive_file" "runner_lambda" {
  type        = "zip"
  source_file = "${path.module}/../lambda/runner_handler.py"
  output_path = "${path.module}/runner_lambda.zip"
}

data "archive_file" "healthcheck_lambda" {
  type        = "zip"
  source_file = "${path.module}/../lambda/healthcheck_handler.py"
  output_path = "${path.module}/healthcheck_lambda.zip"
}

# ---------- IAM: Trigger Lambda ----------
resource "aws_iam_role" "trigger_lambda" {
  name = "waf-report-trigger-lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "trigger_lambda_permissions" {
  name = "trigger-permissions"
  role = aws_iam_role.trigger_lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = ["${aws_s3_bucket.findings.arn}/markers/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = [aws_lambda_function.runner.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/lambda/*"]
      },
    ]
  })
}

# ---------- IAM: Runner Lambda ----------
resource "aws_iam_role" "runner_lambda" {
  name = "waf-report-runner-lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "runner_lambda_permissions" {
  name = "runner-permissions"
  role = aws_iam_role.runner_lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["bedrock-agentcore:InvokeAgentRuntime"]
        Resource = [
          aws_bedrockagentcore_agent_runtime.supervisor.agent_runtime_arn,
          "${aws_bedrockagentcore_agent_runtime.supervisor.agent_runtime_arn}/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = ["${aws_s3_bucket.findings.arn}/markers/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/lambda/*"]
      },
    ]
  })
}

# ---------- IAM: Healthcheck Lambda ----------
resource "aws_iam_role" "healthcheck_lambda" {
  name = "waf-report-healthcheck-lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "healthcheck_lambda_permissions" {
  name = "healthcheck-permissions"
  role = aws_iam_role.healthcheck_lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = [aws_s3_bucket.findings.arn]
        Condition = {
          StringLike = { "s3:prefix" = ["markers/*"] }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:DeleteObject"]
        Resource = ["${aws_s3_bucket.findings.arn}/markers/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [local.sns_topic_arn]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/lambda/*"]
      },
    ]
  })
}

# ---------- Lambda functions ----------
resource "aws_lambda_function" "trigger" {
  function_name    = "waf-report-trigger"
  role             = aws_iam_role.trigger_lambda.arn
  handler          = "trigger_handler.handler"
  runtime          = "python3.11"
  timeout          = 60
  filename         = data.archive_file.trigger_lambda.output_path
  source_code_hash = data.archive_file.trigger_lambda.output_base64sha256

  environment {
    variables = {
      REGION               = var.region
      FINDINGS_BUCKET      = aws_s3_bucket.findings.id
      RUNNER_FUNCTION_NAME = aws_lambda_function.runner.function_name
      LOOKBACK_HOURS       = "24"
      DRY_RUN              = "true"
    }
  }
}

resource "aws_lambda_function" "runner" {
  function_name    = "waf-report-runner"
  role             = aws_iam_role.runner_lambda.arn
  handler          = "runner_handler.handler"
  runtime          = "python3.11"
  timeout          = 900
  filename         = data.archive_file.runner_lambda.output_path
  source_code_hash = data.archive_file.runner_lambda.output_base64sha256

  environment {
    variables = {
      REGION                 = var.region
      FINDINGS_BUCKET        = aws_s3_bucket.findings.id
      SUPERVISOR_RUNTIME_ARN = aws_bedrockagentcore_agent_runtime.supervisor.agent_runtime_arn
      LOOKBACK_HOURS         = "24"
      DRY_RUN                = "true"
    }
  }
}

resource "aws_lambda_function" "healthcheck" {
  function_name    = "waf-report-healthcheck"
  role             = aws_iam_role.healthcheck_lambda.arn
  handler          = "healthcheck_handler.handler"
  runtime          = "python3.11"
  timeout          = 60
  filename         = data.archive_file.healthcheck_lambda.output_path
  source_code_hash = data.archive_file.healthcheck_lambda.output_base64sha256

  environment {
    variables = {
      REGION                 = var.region
      FINDINGS_BUCKET        = aws_s3_bucket.findings.id
      SNS_TOPIC_ARN          = local.sns_topic_arn
      HANG_THRESHOLD_MINUTES = tostring(var.healthcheck_hang_threshold_minutes)
      RUNNER_FUNCTION_NAME   = aws_lambda_function.runner.function_name
    }
  }
}

# ---------- Async retry lockdown (Lambda event invoke config) ----------
# healthcheck is sync-invoked, so it doesn't need this.
resource "aws_lambda_function_event_invoke_config" "trigger" {
  function_name                = aws_lambda_function.trigger.function_name
  maximum_retry_attempts       = 0
  maximum_event_age_in_seconds = 60
}

resource "aws_lambda_function_event_invoke_config" "runner" {
  function_name                = aws_lambda_function.runner.function_name
  maximum_retry_attempts       = 0
  maximum_event_age_in_seconds = 60
}

# ---------- Permission for EventBridge Scheduler to invoke Lambdas ----------
resource "aws_lambda_permission" "scheduler_invoke_trigger" {
  statement_id  = "AllowSchedulerInvokeTrigger"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.trigger.function_name
  principal     = "scheduler.amazonaws.com"
}

resource "aws_lambda_permission" "scheduler_invoke_healthcheck" {
  statement_id  = "AllowSchedulerInvokeHealthcheck"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.healthcheck.function_name
  principal     = "scheduler.amazonaws.com"
}

# ---------- EventBridge Scheduler IAM (shared by A and B) ----------
resource "aws_iam_role" "scheduler_eventbridge" {
  name = "waf-report-scheduler-eventbridge"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "scheduler_eventbridge_invoke" {
  name = "invoke-lambdas"
  role = aws_iam_role.scheduler_eventbridge.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["lambda:InvokeFunction"]
      Resource = [
        aws_lambda_function.trigger.arn,
        "${aws_lambda_function.trigger.arn}:*",
        aws_lambda_function.healthcheck.arn,
        "${aws_lambda_function.healthcheck.arn}:*",
      ]
    }]
  })
}

# ---------- EventBridge Scheduler A (trigger, async fire-and-forget) ----------
resource "aws_scheduler_schedule" "daily_waf_scan" {
  name                         = "waf-report-daily-scan"
  state                        = var.schedule_enabled ? "ENABLED" : "DISABLED"
  schedule_expression          = var.schedule_expression
  schedule_expression_timezone = var.schedule_timezone

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = "arn:aws:scheduler:::aws-sdk:lambda:invoke"
    role_arn = aws_iam_role.scheduler_eventbridge.arn
    input = jsonencode({
      FunctionName   = aws_lambda_function.trigger.arn
      InvocationType = "Event"
      Payload        = ""
    })
    retry_policy {
      maximum_retry_attempts       = 0
      maximum_event_age_in_seconds = 60
    }
  }
}

# ---------- EventBridge Scheduler B (healthcheck, sync retries=0) ----------
resource "aws_scheduler_schedule" "daily_waf_healthcheck" {
  name                         = "waf-report-daily-healthcheck"
  state                        = var.schedule_enabled ? "ENABLED" : "DISABLED"
  schedule_expression          = var.healthcheck_schedule_expression
  schedule_expression_timezone = var.schedule_timezone

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.healthcheck.arn
    role_arn = aws_iam_role.scheduler_eventbridge.arn
    retry_policy {
      maximum_retry_attempts       = 0
      maximum_event_age_in_seconds = 60
    }
  }
}

# ============================================================
# Outputs
# ============================================================
output "supervisor_runtime_arn" {
  value = aws_bedrockagentcore_agent_runtime.supervisor.agent_runtime_arn
}

output "analyzer_runtime_arn" {
  value = aws_bedrockagentcore_agent_runtime.analyzer.agent_runtime_arn
}

output "validator_runtime_arn" {
  value = aws_bedrockagentcore_agent_runtime.validator.agent_runtime_arn
}


output "executor_runtime_arn" {
  value = aws_bedrockagentcore_agent_runtime.executor.agent_runtime_arn
}

output "gateway_id" {
  value = aws_bedrockagentcore_gateway.waf_tools.gateway_id
}

output "memory_id" {
  value = aws_bedrockagentcore_memory.waf_findings.id
}

output "sns_topic_arn" {
  value = local.sns_topic_arn
}

output "ecr_repositories" {
  value = { for k, v in aws_ecr_repository.agents : k => v.repository_url }
}

output "trigger_lambda_arn" {
  value = aws_lambda_function.trigger.arn
}

output "runner_lambda_arn" {
  value = aws_lambda_function.runner.arn
}

output "healthcheck_lambda_arn" {
  value = aws_lambda_function.healthcheck.arn
}

output "daily_scan_schedule_name" {
  value = aws_scheduler_schedule.daily_waf_scan.name
}

output "daily_healthcheck_schedule_name" {
  value = aws_scheduler_schedule.daily_waf_healthcheck.name
}

output "findings_bucket" {
  value = aws_s3_bucket.findings.id
}
