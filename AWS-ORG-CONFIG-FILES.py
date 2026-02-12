import os
import json
import time
import boto3
import smtplib
import gzip
import base64
import csv
import io
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from botocore.exceptions import ClientError

# ========= AUDIT CONFIGS =========
TARGET_ROLE_NAME = os.environ.get("TARGET_ROLE_NAME", "CUST_REQ_CONFIG_AUDIT")
TARGET_REGION = os.environ.get("TARGET_REGION", "us-east-1")

# ========= EMAIL CONFIGS (SMTP) =========
SES_SMTP_USER = os.environ.get("SES_SMTP_USER")
SES_SMTP_PASSWORD = os.environ.get("SES_SMTP_PASSWORD")
SES_HOST = "email-smtp.us-east-1.amazonaws.com"
SES_PORT = 587
MAIL_FROM = os.environ.get("MAIL_FROM", "mpsjr1978@gmail.com")
MAIL_TO = os.environ.get("MAIL_TO", "mpsjr1978@gmail.com").split(',')

# ========= ENVIRONMENTS WITHOUT REDIS =========
ENVIRONMENTS_WITHOUT_REDIS = ["*-WEB", "*-PRD", "*-QA"]

# ========= DEFAULT EXPECTED VALUES =========
EXPECTED_DEFAULTS = {
    # ahd.ini
    "MaxPoolSize": {
        "expected": "*",      "type": "int",        "severity": "warn"
    },
    "ConnectionLifetime": {
        "expected": "*",      "type": "int",        "severity": "warn"
    },
    "QueryTimeOut": {
        "expected": 300,      "type": "int",        "severity": "warn"
    },
    "ConnectTimeOut": {
        "expected": 30,       "type": "int",        "severity": "warn"
    },
    # web.config
    "httpRuntime.executionTimeout": {
        "expected": 600,      "type": "int",        "severity": "warn"
    },
    "httpRuntime.maxRequestLength": {
        "expected": 102400,   "type": "int",        "severity": "warn"
    },
    "httpRuntime.requestValidationMode": {
        "expected": "2.0",    "type": "str",        "severity": "warn"
    },
    "httpRuntime.targetFramework": {
        "expected": "4.8",    "type": "str",        "severity": "warn"
    },
    # Redis
    "RedisSessionStateStore.connectionTimeoutInMilliseconds": {
        "expected": 60000,    "type": "int",        "severity": "warn"
    },
    "RedisSessionStateStore.operationTimeoutInMilliseconds": {
        "expected": 60000,    "type": "int",        "severity": "warn"
    },
    "RedisSessionStateStore.retryTimeoutInMilliseconds": {
        "expected": 300000,   "type": "int",        "severity": "warn"
    },
    # Services
    "log.enabled": {
        "expected": "true",   "type": "str",        "severity": "warn"
    },
}

# ========= Accounts list =========
TARGET_ACCOUNTS = [
    {"Id": "xxxxxxxxxxx", "Name": "AWS Account X"},
    #{"Id": "yyyyyyyyyyy", "Name": "AWS Account Y"},
    {"Id": "zzzzzzzzzzzz", "Name": "AWS Account Z"},
]

# Clients AWS
sts_client = boto3.client("sts")

# ==============================================================================
#  AUX FUNCTIONS (SSM / ASSUME ROLE)
# ==============================================================================

def assume_role_in_account(account_id, role_name, current_account_id):
    if account_id == current_account_id:
        return boto3.Session(region_name=TARGET_REGION)
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        resp = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=f"audit-{account_id}")
        creds = resp["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=TARGET_REGION,
        )
    except Exception as e:
        print(f"[ERRO] Assume Role failed {account_id}: {e}")
        return None

def get_instance_ids_with_tag(session, tag_substrings):
    ec2 = session.client("ec2")
    instances = []
    seen_names = set() 

    try:
        paginator = ec2.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    if instance.get("State", {}).get("Name") != "running":
                        continue
                        
                    name = next((t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"), "Unknown")
                    
                    if any(sub in name for sub in tag_substrings):
                        if name in seen_names:
                            print(f" [SKIP] Duplicate Instance (same Name tag): {name} - ID: {instance['InstanceId']}")
                            continue
                        
                        seen_names.add(name)
                        instances.append({"InstanceId": instance["InstanceId"], "InstanceName": name})
    except Exception as e:
        print(f"[WARN] Error to list instances: {e}")
        pass
    return instances

def run_ssm_test(session, instance_id, script):
    ssm = session.client("ssm")
    try:
        resp = ssm.send_command(InstanceIds=[instance_id], DocumentName="AWS-RunPowerShellScript", Parameters={"commands": [script]})
        cmd_id = resp["Command"]["CommandId"]
        for _ in range(30):
            time.sleep(2)
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
            if inv["Status"] in ["Success", "Failed", "TimedOut"]:
                return inv.get("StandardOutputContent", "{}"), inv.get("StandardErrorContent", "")
    except Exception as e:
        return "{}", str(e)
    return "{}", "Timeout/Error"

# ==============================================================================
#  PROCESS LOGIC (CORE)
# ==============================================================================

def infer_env(instance_name):
    name = (instance_name or "").lower()
    if "sd-web" in name or "sd-api" in name or "sd-qp" in name or "sd-app" in name: return "SD-PRD"
    if "sd-qa-dev" in name: return "SD-QA-DEV"
    if "prd" in name: return "PRD"
    if "qa" in name: return "QA"
    if "dev" in name: return "DEV"
    if "apr" in name: return "APR"
    if "poc" in name: return "POC"
    return "-"

def normalize_value_for_compare(value, value_type="str"):
    if value is None: return None
    if isinstance(value, list):
        value = value[0] if len(value) > 0 else None
        if value is None: return None
        
    s = str(value).strip()
    if s.lower() in ("n/a", "na", "none", "null", "", "not found"): return None

    try:
        if value_type == "int": return int(s)
        if value_type == "float": return float(s)
        if value_type == "bool": return s.lower() in ("true", "1", "yes", "y", "sim")
    except Exception:
        return s
    return s

def format_display_value(param, val):
    temp_val = val
    if isinstance(val, list) and len(val) > 0:
        temp_val = val[0]
    elif isinstance(val, list):
        return str(val), False

    if temp_val is None: return "MISSING (NULL)", False
    
    # Specific conversion to MaxRequestLength (KB -> MB)
    if param == "httpRuntime.maxRequestLength":
        try:
            str_val = str(temp_val).strip()
            mb_val = float(str_val) / 1024
            return f"{mb_val:.1f} MB", True 
        except:
            pass
    
    s = str(temp_val).strip()
    try:
        float(s)
        return s, True
    except:
        return s, False

def process_audit_results(all_results):
    """
    Proccess the JSON file from all instanes and return a list with the records
    ready to be consumed by the HTML and CSV
    """
    findings = []
    
    instance_stats = {} 
    total_issues_count = 0

    for item in all_results:
        acc_name = item.get("AccountName", "N/A")
        inst_name = item.get("InstanceName", "N/A")
        env = infer_env(inst_name)
        stdout_raw = item.get("StdOut", "{}")

        inst_key = (acc_name, inst_name, env)
        if inst_key not in instance_stats:
            instance_stats[inst_key] = {"warn": 0, "error": 0, "out": 0, "total": 0}

        # Decode JSON
        data = {}
        try:
            if not stdout_raw.strip(): continue
            clean_stdout = stdout_raw.strip().lstrip('\ufeff').replace("\n", "").replace("\r", "").replace(" ", "")
            try:
                decoded_bytes = base64.b64decode(clean_stdout)
                decompressed_str = gzip.decompress(decoded_bytes).decode('utf-8-sig')
                data = json.loads(decompressed_str)
            except Exception:
                data = json.loads(stdout_raw)
        except json.JSONDecodeError as e:
            # Record JSON error
            findings.append({
                "Account": acc_name, "Instance": inst_name, "Env": env,
                "Context": "-", "File": "-", "Param": "JSON_ERROR",
                "Value": f"Failed to read JSON: {str(e)}", "Expected": "-", 
                "Status": "ERROR", "StatusClass": "status-error", "IsIssue": True
            })
            instance_stats[inst_key]["error"] += 1
            instance_stats[inst_key]["total"] += 1
            total_issues_count += 1
            continue

        # Proscess the content
        for context_name, files in (data or {}).items():
            for file_type, params in (files or {}).items():
                
                # File error (File Not Found, etc)
                if isinstance(params, list):
                    # Searchs for the first item in the list that is a dictionary
                    found_dict = next((i for i in params if isinstance(i, dict)), None)
                    # If found it, use it. If not, uses an empty dictionary to not break.
                    params = found_dict if found_dict is not None else {}

                # Extra security: if params is not dict (ex: string), jump it
                if not isinstance(params, dict):
                    continue
                    
                    findings.append({
                        "Account": acc_name, "Instance": inst_name, "Env": env,
                        "Context": context_name, "File": file_type, "Param": "FileStatus",
                        "Value": params, "Expected": "Exists", 
                        "Status": "ERROR", "StatusClass": "status-error", "IsIssue": True
                    })
                    instance_stats[inst_key]["error"] += 1
                    instance_stats[inst_key]["total"] += 1
                    total_issues_count += 1
                    continue

                # Validate params
                for param, value in (params or {}).items():
                    if context_name == "_ServerServices" and str(value) == "Not Found": continue
                    if "RedisSessionStateStore" in param and str(value) == "Not Found" and file_type != "WEB_AppConfig": continue

                    value_fmt, is_numeric = format_display_value(param, value)
                    
                    status_code = "OK"
                    status_class = ""
                    expected_fmt = "-"
                    is_issue = False
                    severity_tag = None

                    # 1. Check Errors/Nulls
                    if value is None or value == "null":
                        status_code = "WARN"
                        status_class = "status-warn"
                        severity_tag = "warn"
                        is_issue = True
                    elif "Error" in str(param) or "Error" in str(value):
                        status_code = "ERROR"
                        status_class = "status-error"
                        severity_tag = "error"
                        is_issue = True
                    else:
                        # 2. Check unesppected values
                        expected_info = EXPECTED_DEFAULTS.get(param)
                        if expected_info is not None:
                            expected_val = expected_info.get("expected")
                            vtype = expected_info.get("type", "str")
                            severity = expected_info.get("severity", "warn")

                            norm_curr = normalize_value_for_compare(value, vtype)
                            # If norm_curr is None, it cames "N/A", "null" ou empty.
                            # If the rule is "*", we just consider error if the value is None (N/A)
                            if expected_val == "*":
                                if norm_curr is None:
                                    # It's an error N/A
                                    status_code = "MISSING" if severity != "error" else "ERROR"
                                    status_class = "status-warn" if severity == "warn" else "status-error"
                                    severity_tag = severity
                                    is_issue = True
                                    expected_fmt = "Required"
                                else:
                                    # If it has value, it's approved
                                    # Status OK to the report
                                    expected_fmt = "Any" 
                            # ------------------------
                            
                            else:
                                norm_exp = normalize_value_for_compare(expected_val, vtype)

                                if norm_curr is not None and norm_exp is not None and norm_curr != norm_exp:
                                    status_code = "OUT_STD" if severity not in ["error", "warn"] else severity.upper()
                                    status_class = "status-error" if severity == "error" else "status-warn" if severity == "warn" else "status-out-of-standard"
                                    severity_tag = severity if severity in ["error", "warn"] else "out"
                                    is_issue = True
                                    expected_fmt, _ = format_display_value(param, expected_val)

                    # Accounting Stats
                    if is_issue:
                        if severity_tag == "error": instance_stats[inst_key]["error"] += 1
                        elif severity_tag == "out": instance_stats[inst_key]["out"] += 1
                        else: instance_stats[inst_key]["warn"] += 1
                        total_issues_count += 1
                    
                    instance_stats[inst_key]["total"] += 1

                    findings.append({
                        "Account": acc_name, "Instance": inst_name, "Env": env,
                        "Context": context_name, "File": file_type, "Param": param,
                        "Value": value_fmt, "Expected": expected_fmt,
                        "Status": status_code, "StatusClass": status_class, 
                        "IsIssue": is_issue, "IsNumeric": is_numeric
                    })

    return findings, instance_stats, total_issues_count

# ==============================================================================
#  VIEW GENERATORS (HTML & CSV)
# ==============================================================================

def generate_csv_content(findings):
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    
    # Header
    writer.writerow(["Conta", "Instancia", "Ambiente", "Cliente_Contexto", "Arquivo", "Parametro", "Valor_Encontrado", "Valor_Esperado", "Status"])
    
    for f in findings:
        writer.writerow([
            f["Account"], f["Instance"], f["Env"], f["Context"], 
            f["File"], f["Param"], f["Value"], f["Expected"], f["Status"]
        ])
        
    return output.getvalue()

def generate_html_body(findings, instance_stats, issue_count):
    def env_css_class(env):
        if env == "PRD": return "env-PRD"
        if env == "DEV": return "env-DEV"
        if env == "QA":  return "env-QA"
        return "env-UNK"

    css_style = """
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px; color: #333; margin: 0; padding: 0; }
        h2, h3 { margin: 0 0 5px 0; }
        .container { padding: 16px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 6px 8px; font-size: 12px; }
        th { background-color: #0056b3; color: white; text-align: left; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .status-warn { background-color: #fff3cd; color: #856404; font-weight: bold; }
        .status-error { background-color: #f8d7da; color: #721c24; font-weight: bold; }
        .status-out-of-standard { background-color: #d1ecf1; color: #0c5460; font-weight: bold; }
        .header-info { padding: 12px 16px; background-color: #e9ecef; border-left: 5px solid #0056b3; margin-bottom: 20px; }
        .legend { margin-bottom: 10px; font-size: 12px; }
        .legend span { display: inline-block; margin-right: 12px; padding: 3px 6px; border-radius: 3px; }
        .legend .lg-warn { background-color: #fff3cd; color: #856404; }
        .legend .lg-error { background-color: #f8d7da; color: #721c24; }
        .legend .lg-out { background-color: #d1ecf1; color: #0c5460; }
        .env-pill { display: inline-block; padding: 2px 6px; border-radius: 10px; font-size: 11px; font-weight: 600; }
        .env-DEV {background-color: #e3f2fd; color:#0d47a1;}
        .env-QA {background-color: #f3e5f5;color:#4a148c;}
        .env-PRD {background-color: #ede7f6;color:#311b92;}
        .env-UNK {background-color: #eceff1;color:#37474f;}
        .param-name { font-family: Consolas, 'Courier New', monospace; font-size: 12px; }
        .value-cell { font-family: Consolas, 'Courier New', monospace; font-size: 12px; }
        .value-right { text-align: right; }
        .summary-table th, .summary-table td { font-size: 12px; }
        .summary-table th { background-color: #343a40; }
        .badge { display: inline-block; padding: 2px 6px; border-radius: 10px; font-size: 11px; }
        .badge-warn { background-color: #fff3cd; color: #856404; }
        .badge-error { background-color: #f8d7da; color: #721c24; }
        .badge-out { background-color: #d1ecf1; color: #0c5460; }
    </style>
    """

    summary_rows = ""
    for (acc, inst, env), stats in sorted(instance_stats.items(), key=lambda x: (x[0][0], x[0][2], x[0][1])):
        env_class = env_css_class(env)
        summary_rows += f"""<tr><td>{acc}</td><td>{inst}</td><td><span class="env-pill {env_class}">{env}</span></td><td><span class="badge badge-warn">{stats['warn']}</span></td><td><span class="badge badge-error">{stats['error']}</span></td><td><span class="badge badge-out">{stats['out']}</span></td><td>{stats['total']}</td></tr>"""

    detail_rows = ""
    for f in findings:
        env_class = env_css_class(f["Env"])
        val_cls = "value-cell" + (" value-right" if f.get("IsNumeric") else "")
        val_display = f["Value"]
        if f["IsIssue"] and f["Expected"] != "-":
            val_display = f"{f['Value']} (Esperado: {f['Expected']})"
            
        detail_rows += f"""<tr class="{f.get('StatusClass', '')}"><td>{f['Account']}</td><td>{f['Instance']}</td><td><span class="env-pill {env_class}">{f['Env']}</span></td><td>{f['Context']}</td><td>{f['File']}</td><td class="param-name">{f['Param']}</td><td class="{val_cls}">{val_display}</td></tr>"""

    return f"""<html><head>{css_style}</head><body><div class="container"><div class="header-info"><h2>RelatÃ³rio de Auditoria de Arquivos de ConfiguraÃ§Ã£o application</h2><p><b>Alerts:</b> {issue_count}. Segue planilha detalhada em anexo.</p></div><div class="legend"><span class="lg-warn">Warning</span><span class="lg-error">Error</span><span class="lg-out">Fora PadrÃ£o</span></div><h3>Resumo</h3><table class="summary-table"><thead><tr><th>Conta</th><th>InstÃ¢ncia</th><th>Ambiente</th><th>Warn</th><th>Err</th><th>Out</th><th>Total</th></tr></thead><tbody>{summary_rows}</tbody></table><h3>Detalhes</h3><table><thead><tr><th>Conta</th><th>InstÃ¢ncia</th><th>Amb</th><th>Contexto</th><th>Arquivo</th><th>Param</th><th>Valor</th></tr></thead><tbody>{detail_rows}</tbody></table></div></body></html>"""

# ==============================================================================
#  EMAIL SEND (WITH ATTACHMMENT)
# ==============================================================================

def send_email_with_report(subject, html_body, csv_content):
    msg = MIMEMultipart()
    msg['From'] = MAIL_FROM
    msg['To'] = ", ".join(MAIL_TO)
    msg['Subject'] = subject

    # HTML BODY
    msg.attach(MIMEText(html_body, 'html'))

    # CSV Attachmment
    attachment = MIMEApplication(csv_content.encode('utf-8'))
    attachment.add_header('Content-Disposition', 'attachment', filename='Relatorio_Auditoria_application.csv')
    msg.attach(attachment)

    try:
        print(f"[SMTP] Connecting to {SES_HOST}...")
        server = smtplib.SMTP(SES_HOST, SES_PORT)
        server.starttls()
        server.login(SES_SMTP_USER, SES_SMTP_PASSWORD)
        server.sendmail(MAIL_FROM, MAIL_TO, msg.as_string())
        server.quit()
        print("[SMTP] E-mail sent.")
    except Exception as e:
        print(f"[SMTP] Error sending e-mail: {str(e)}")

# ==============================================================================
#  MAIN HANDLER
# ==============================================================================

def lambda_handler(event, context):
    powershell_script = r'''
    param (
        [string]$applicationPath = "C:\inetpub\wwwroot",
        [string]$applicationAppPath = "C:\"
    )
    $ErrorActionPreference = 'SilentlyContinue'
    $CheckRedisGlobal = __CHECK_REDIS_BOOL__ 

    function Validate-AhdIni {
        param($path, [bool]$checkDataHub = $false) 
        
        $result = @{}
        if (-not (Test-Path $path)) { return $null }
        try {
            $iniContent = Get-Content $path -ErrorAction Stop | Out-String
            
            $result["QueryTimeOut"] = if ($iniContent -match "(?m)^\s*QueryTimeOut\s*=\s*(\d+)") { $matches[1] } else { "Not Found" }
            $result["ConnectTimeOut"] = if ($iniContent -match "(?m)^\s*ConnectTimeOut\s*=\s*(\d+)") { $matches[1] } else { "Not Found" }
            $result["ConnectionLifetime"] = if ($iniContent -match '(?im)(?:^\s*|^\s*Attributes\s*=\s*".*?)(?:Connection Lifetime|ConnectionLifetime)\s*=\s*(\d+)') { $matches[1] } else { "Not Found" }
            $result["MaxPoolSize"] = if ($iniContent -match '(?im)(?:^\s*|^\s*Attributes\s*=\s*".*?)(?:Max Pool Size|MaxPoolSize)\s*=\s*(\d+)') { $matches[1] } else { "Not Found" }
            
            if ($checkDataHub) {
                $result["DATAHUB"] = if ($iniContent -match "(?im)^\s*\[DATAHUB\]") { "OK" } else { "Not Found" }
            }
            
        } catch { $result["Error"] = "Read Error" }
        return $result
    }
    
    function Validate-WebConfig {
        param($path, [bool]$checkRedis = $false, [bool]$checkAPP, [bool]$checkAPI, [bool]$checkQP, [bool]$checkDH)
        $result = @{}
        if (-not (Test-Path $path)) { return $null }
        try {
            [xml]$xml = Get-Content $path -ErrorAction Stop
            
            $rootSysWeb = $null
            $rootSecurity = $null
            $locSysWeb = $null
            
            if ($xml.configuration."system.web") { 
                $rootSysWeb = $xml.configuration."system.web" 
            }
            
            if ($xml.configuration.location) {
                $locations = @($xml.configuration.location)
                foreach ($loc in $locations) {
                    # Verifica path vazio ou "."
                    if ($loc.path -eq "" -or $loc.path -eq ".") {
                        if ($loc."system.web") {
                            $locSysWeb = $loc."system.web"
                            break
                        }
                    }
                }
            }

            if ($xml.configuration.application.security) { 
                $rootSecurity = $xml.configuration.application.security
            }

            if ($checkAPP) {
                if ($rootSysWeb) {
                    $result["httpRuntime.executionTimeout"]  = $rootSysWeb.httpRuntime.executionTimeout
                    $result["httpRuntime.maxRequestLength"]  = $rootSysWeb.httpRuntime.maxRequestLength
                    $result["httpRuntime.targetFramework"]   = $rootSysWeb.httpRuntime.targetFramework
                    $result["httpRuntime.requestValidationMode"] = $rootSysWeb.httpRuntime.requestValidationMode
                    $result["tenantIsolation.allowReportsConnectionString"] = $rootSecurity.tenantIsolation.allowReportsConnectionString
                    
                    if ($rootSysWeb.machineKey) {
                        $result["machineKey"] = $true
                    } else {
                        $result["machineKey"] = $false
                    }
                } else {
                    $result["Error_APP_Root"] = "Root <system.web> section not found"
                }

                if ($checkRedis) {
                    $redis = $null
                    
                    function Find-Redis ($sysWebObj) {
                        if ($sysWebObj -and $sysWebObj.sessionState -and $sysWebObj.sessionState.providers -and $sysWebObj.sessionState.providers.add) {
                            return @($sysWebObj.sessionState.providers.add) | Where-Object { $_.name -eq "RedisSessionStateStore" } | Select-Object -First 1
                        }
                        return $null
                    }

                    $redis = Find-Redis $locSysWeb
                    
                    if (-not $redis) {
                        $redis = Find-Redis $rootSysWeb
                    }

                    if ($redis) {
                        $result["RedisSessionStateStore.connectionTimeoutInMilliseconds"] = $redis.connectionTimeoutInMilliseconds
                        $result["RedisSessionStateStore.operationTimeoutInMilliseconds"] = $redis.operationTimeoutInMilliseconds
                        $result["RedisSessionStateStore.retryTimeoutInMilliseconds"]      = $redis.retryTimeoutInMilliseconds
                    } else {
                        $result["RedisSessionStateStore.connectionTimeoutInMilliseconds"] = "Not Found"
                        $result["RedisSessionStateStore.operationTimeoutInMilliseconds"] = "Not Found"
                        $result["RedisSessionStateStore.retryTimeoutInMilliseconds"] = "Not Found"
                    }
                }
            }
            
            # --- Validations API/QP/DH ---
            if ($checkAPI) {
                $auth = $xml.configuration.applcation.'authorization.settings'
                if ($auth -and $auth.tokens) {
                    $result["httpRuntime.targetFramework"] = $rootSysWeb.httpRuntime.targetFramework
                    $result["tokens.enablePrivateTokens"] = $auth.tokens.enablePrivateTokens
                    $result["tokens.name"] = $auth.tokens.add.name
                } else { $result["tokens"] = "Not Found" }
            }
            if ($checkQP) {
                $qpSecurity = $xml.configuration.application.'queryprocessor.security'
                if ($qpSecurity -and $qpSecurity.tenantIsolation) {
                    $result["httpRuntime.targetFramework"] = $rootSysWeb.httpRuntime.targetFramework
                    $tenant = $qpSecurity.tenantIsolation
                    $result["tenantIsolation.allowQueryProcessorConnectionString"] = $tenant.allowQueryProcessorConnectionString
                    $result["tenantIsolation.allowQueryProcessorShell"]            = $tenant.allowQueryProcessorShell
                    $result["tenantIsolation.allowQueryProcessorExcel"]            = $tenant.allowQueryProcessorExcel
                } else { 
                    $result["tenantIsolation.allowQueryProcessorConnectionString"] = "Not Found"
                    $result["tenantIsolation.allowQueryProcessorShell"] = "Not Found"
                    $result["tenantIsolation.allowQueryProcessorExcel"] = "Not Found"
                }
            }
            if ($checkDH) {
                # Safe navigation. Sometimes the XML is Case-Sensitive to the .NET objects
                # Structure: <configuration> -> <application> -> <dataHub>
                $reqSection = $xml.configuration.application
                
                if ($reqSection -and $reqSection.dataHub) {
                    $datahub = $reqSection.dataHub
                    
                    if ($datahub.parquet) {
                        $result["parquet.defaultTop"] = $datahub.parquet.defaultTop
                        $result["parquet.maxTop"]     = $datahub.parquet.maxTop
                    } else { $result["parquet"] = "Not Found" }
                    
                    if ($datahub.json) {
                        $result["json.defaultTop"]    = $datahub.json.defaultTop
                        $result["json.maxTop"]        = $datahub.json.maxTop
                    } else { $result["json"] = "Not Found" }
                    
                    if ($datahub.log) {
                        $result["log.level"]          = $datahub.log.level
                    } else { $result["log"] = "Not Found" }
                    
                } else {
                    $result["DataHubSection"] = "Not Found"
                }
            }
            
            if ($result.Count -eq 0) { $result["Info"] = "No checks performed" }
        } catch { $result["Error"] = "Invalid XML: " + $_.Exception.Message }
        return $result
    }

    function Validate-ServiceConfig {
        param($path, $type)
        $result = @{}
        if (-not (Test-Path $path)) { $result["Status"] = "Not Found"; return $result }
        try {
            [xml]$xml = Get-Content $path -ErrorAction Stop
            if ($type -eq "Event") {
                $result["log.enabled"] = $xml.configuration.eventservice.'log'.enabled
                $result["log.path"] = $xml.configuration.eventservice.'log'.path
            } elseif ($type -eq "Messaging") {
                $result["debug.enabled"] = $xml.configuration.'application.messaging'.'debug'.enabled
            } elseif ($type -eq "Blob") {
                $result["settings.interval"] = $xml.configuration.application.'redirect.settings'.interval
                $result["settings.filenameMaxSize"] = $xml.configuration.application.'redirect.settings'.filenameMaxSize
                $result["search.bufferSize"] = $xml.configuration.application.'redirect.settings'.search.bufferSize
            }
        } catch { $result["Error"] = "XML Error" }
        return $result
    }
    
    function Validate-ConfigFiles {
        $allResults = @{}
        function Get-OrCreateClientEntry ($name) { if (-not $allResults.ContainsKey($name)) { $allResults[$name] = @{} } }

        if (Test-Path $applicationPath) {
            $webFolders = Get-ChildItem -Path $applicationPath -Directory
            foreach ($folder in $webFolders) {
                $customerName = $folder.Name
                Get-OrCreateClientEntry $customerName
                
                $res = Validate-AhdIni -path (Join-Path $folder.FullName "ahd.ini") -checkDataHub $true
                if ($res) { $allResults[$customerName]["WEB_ahd.ini"] = $res }

                $res = Validate-WebConfig -path (Join-Path $folder.FullName "application\web.config") -checkRedis $CheckRedisGlobal -checkAPP $true
                if ($res) { $allResults[$customerName]["WEB_AppConfig"] = $res }
                
                $res = Validate-WebConfig -path (Join-Path $folder.FullName "dataservices\web.config") -checkRedis $false -checkAPI $true
                if ($res) { $allResults[$customerName]["WEB_DataServices"] = $res }
                
                $res = Validate-WebConfig -path (Join-Path $folder.FullName "queryprocessor\web.config") -checkRedis $false -checkQP $true
                if ($res) { $allResults[$customerName]["WEB_QueryProcessors"] = $res }

                $res = Validate-WebConfig -path (Join-Path $folder.FullName "datahub\web.config") -checkRedis $false -checkDH $true
                if ($res) { $allResults[$customerName]["WEB_Datahub"] = $res }
            }
        }

        if (Test-Path $applicationAppPath) {
            $appFolders = Get-ChildItem -Path $applicationAppPath -Directory
            foreach ($folder in $appFolders) {
                $customerName = $folder.Name
                Get-OrCreateClientEntry $customerName
                $res = Validate-AhdIni -path (Join-Path $folder.FullName "ahd.ini") -checkDataHub $false
                if ($res) { $allResults[$customerName]["APP_ahd.ini"] = $res }

                $resEvt = Validate-ServiceConfig -path (Join-Path $folder.FullName "EventServices\EventServicesSvc.exe.config") -type "Event"
                if ($resEvt.Status -ne "Not Found") { $allResults[$customerName]["APP_EventServices"] = $resEvt }

                $msgPath = Join-Path $folder.FullName "MessagingService\MessagingService.exe.config"
                if (-not (Test-Path $msgPath)) { $msgPath = Join-Path $folder.FullName "MessagingServices\MessagingService.exe.config" }
                $resMsg = Validate-ServiceConfig -path $msgPath -type "Messaging"
                if ($resMsg.Status -ne "Not Found") { $allResults[$customerName]["APP_MessagingServices"] = $resMsg }

                $blobPath = Join-Path $folder.FullName "BlobTransport\BlobTransportSvc.exe.config"
                if (-not (Test-Path $blobPath)) { $blobPath = Join-Path $folder.FullName "BlobTransport\BlobTransportSvc.exe.config" }
                $resBlob = Validate-ServiceConfig -path $blobPath -type "Blob"
                if ($resBlob.Status -ne "Not Found") { $allResults[$customerName]["APP_BlobTransport"] = $resBlob }
            }
        }
        try {
            $finalJson = $allResults | ConvertTo-Json -Depth 5
            $memStream = [System.IO.MemoryStream]::new()
            $gzipStream = [System.IO.Compression.GZipStream]::new($memStream, [System.IO.Compression.CompressionMode]::Compress)
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.Encoding]::UTF8)
            $writer.Write($finalJson)
            $writer.Dispose()
            return [Convert]::ToBase64String($memStream.ToArray())
        } catch { return $allResults | ConvertTo-Json -Depth 5 }
    }
    try { Validate-ConfigFiles } catch { @{ Error = "Fatal Script Error: " + $_.Exception.Message } | ConvertTo-Json }
    ''' 
    
    if len(powershell_script) < 100:
        return {"Error": "Empty script"}

    # List with Tag Names (substrings) that must be scanned
    tag_substrings = ["*-PRD","*-QA", "*-WEB"]
    current_account_id = sts_client.get_caller_identity()["Account"]
    
    all_results = []

    for acc in TARGET_ACCOUNTS:
        print(f"Proccessing account: {acc['Name']}")
        session = assume_role_in_account(acc["Id"], TARGET_ROLE_NAME, current_account_id)
        if not session: continue

        instances = get_instance_ids_with_tag(session, tag_substrings)
        for inst in instances:
            print(f" -- Audit {inst['InstanceName']} ({inst['InstanceId']})...")
            
            check_redis_val = "$true"
            if any(env in inst["InstanceName"] for env in ENVIRONMENTS_WITHOUT_REDIS):
                print(f"    [INFO] Redis check DISABLED para {inst['InstanceName']}")
                check_redis_val = "$false"
            
            script_for_instance = powershell_script.replace("__CHECK_REDIS_BOOL__", check_redis_val)
            stdout, stderr = run_ssm_test(session, inst["InstanceId"], script_for_instance)
            
            all_results.append({
                "AccountId": acc["Id"], "AccountName": acc["Name"],
                "InstanceId": inst["InstanceId"], "InstanceName": inst["InstanceName"],
                "StdOut": stdout, "StdErr": stderr
            })

    print("Generating report...")
    
    # 1. Proccessa data
    findings, stats, issue_count = process_audit_results(all_results)
    
    # 2. Generates HTML
    html_report = generate_html_body(findings, stats, issue_count)
    
    # 3. Generates CSV (Excel)
    csv_report = generate_csv_content(findings)
    
    subject = f"[AUDIT] Configuration Files Report - {issue_count} Alerts"
    if issue_count == 0:
        subject = "[AUDIT] Configuration Files Report - Success (Without Alerts)"

    # 4. Send E-mail with HTML and Attachmment
    send_email_with_report(subject, html_report, csv_report)

    return {
        "status": "Execution done!",
        "email_sent_to": MAIL_TO,
        "issues_found": issue_count
    }
