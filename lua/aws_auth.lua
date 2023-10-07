local hmac                           = require("openssl").hmac
local resty_sha256                   = require("resty.sha256")
local resty_string                   = require("resty.string")
local readfile                       = require("pl.utils").readfile
local xml                            = require("pl.xml")
local http                           = require("resty.http")
local resty_lock                     = require("resty.lock")

local SIGNED_HEADERS                 = "content-type;host;x-amz-date"
local AWS_SESSION_CACHE_LOCK_TIMEOUT = 3
local AWS_SESSION_DURATION           = 3600 --1 hours
local AWS_SESSION_NAME               = "sqs-proxy-session"
local AWS_ROLE_ARN                   = os.getenv("AWS_ROLE_ARN")
local AWS_REGION                     = os.getenv("AWS_REGION")
local AWS_WEB_IDENTITY_TOKEN_FILE    = os.getenv("AWS_WEB_IDENTITY_TOKEN_FILE")


AWS_SESSION_CACHE_ACCESS_KEY_ID_KEY = "access-key-id"
AWS_SESSION_CACHE_SECRET_ACCESS_KEY = "secret-access-key"
AWS_SESSION_CACHE_SESSION_TOKEN_KEY = "session-token"
AWS_SESSION_CACHE_LOCK_KEY          = "aws_session_cache_lock"


AWSAuth         = {}
AWSAuth.__index = AWSAuth


function AWSAuth:refresh_session()
    local token, err = readfile(AWS_WEB_IDENTITY_TOKEN_FILE)
    if not token then
        return nil, "failed reading token file: " .. err
    end

    local httpc = http.new()
    httpc:set_timeout(5000)

    local url = table.concat({
        "https://sts." .. AWS_REGION .. ".amazonaws.com",
        "?Action=AssumeRoleWithWebIdentity",
        "&DurationSeconds=" .. AWS_SESSION_DURATION,
        "&RoleSessionName=" .. AWS_SESSION_NAME,
        "&RoleArn=" .. AWS_ROLE_ARN,
        "&WebIdentityToken=" .. token,
        "&Version=2011-06-15"
    }, "")

    local response, err = httpc:request_uri(url, { method = "GET", ssl_verify = false })

    if err then
        return nil, "Fail to refresh a session: " .. err
    end

    if response.status ~= 200 then
        return nil, response.body .. " (" .. response.status .. ")"
    end

    local credentials = xml.parse(response.body, nil, true):
    child_with_name("AssumeRoleWithWebIdentityResult"):
    child_with_name("Credentials")

    local access_key_id = credentials:child_with_name("AccessKeyId")[1]
    local secret_access_key = credentials:child_with_name("SecretAccessKey")[1]
    local session_token = credentials:child_with_name("SessionToken")[1]
    local ttl = AWS_SESSION_DURATION - 300

    ngx.shared.aws_session_cache:set(AWS_SESSION_CACHE_ACCESS_KEY_ID_KEY, access_key_id, ttl)
    ngx.shared.aws_session_cache:set(AWS_SESSION_CACHE_SECRET_ACCESS_KEY, secret_access_key, ttl)
    ngx.shared.aws_session_cache:set(AWS_SESSION_CACHE_SESSION_TOKEN_KEY, session_token, ttl)

    return {
        access_key_id = access_key_id,
        secret_access_key = secret_access_key,
        session_token = session_token
    }
end

function AWSAuth:credentials()
    local access_key_id, id_err = ngx.shared.aws_session_cache:get(AWS_SESSION_CACHE_ACCESS_KEY_ID_KEY)
    local secret_access_key, key_err = ngx.shared.aws_session_cache:get(AWS_SESSION_CACHE_SECRET_ACCESS_KEY)
    local session_token, token_err = ngx.shared.aws_session_cache:get(AWS_SESSION_CACHE_SESSION_TOKEN_KEY)

    local err = id_err or key_err or token_err
    if err then
        return nil, "Fail to access to the cache" .. err
    end

    local credentials = nil

    if access_key_id and secret_access_key and session_token then
        credentials = {
            access_key_id = access_key_id,
            secret_access_key = secret_access_key,
            session_token = session_token,
        }
    end

    return credentials, nil
end

function AWSAuth:get_aws_credentials()
    local credentials, err = self:credentials()
    if credentials or err then
        return credentials, err
    end

    local lock, err = resty_lock:new(AWS_SESSION_CACHE_LOCK_KEY, { timeout = AWS_SESSION_CACHE_LOCK_TIMEOUT })
    if not lock then
        return nil, "Fail to create a lock: " .. err
    end

    local _, err = lock:lock(AWS_SESSION_CACHE_LOCK_KEY)
    if err then
        return nil, "Fail to acquire the lock: " .. err
    end

    local credentials, err = self:credentials()
    if credentials or err then
        lock:unlock()
        return credentials, err
    end

    local credentials, err = self:refresh_session()

    lock:unlock()

    return credentials, err
end

local function sha256_digest(s)
    local sha256 = resty_sha256:new()
    sha256:update(s)
    return resty_string.to_hex(sha256:final())
end

local function sign(key, msg)
    return hmac.hmac("sha256", msg, key, true)
end

local function get_signature_key(aws_access_secret, date_stamp, region, service)
    local k_date = sign('AWS4' .. aws_access_secret, date_stamp)
    local k_region = sign(k_date, region)
    local k_service = sign(k_region, service)
    local k_signing = sign(k_service, 'aws4_request')
    return k_signing
end

local function build_signature(params, date_stamp, amz_date)
    local aws_access_secret = params.aws_access_secret
    local region = params.region
    local host = params.host
    local service = params.service
    local content_type = params.content_type
    local method = params.method
    local url = params.url
    local query = params.query or ""
    local body = params.body or ""

    local signing_key = get_signature_key(aws_access_secret, date_stamp, region, service)
    local credential_scope = table.concat({ date_stamp, region, service, 'aws4_request' }, "/")
    local canonical_headers = table.concat({
        "content-type:" .. content_type,
        "host:" .. host,
        "x-amz-date:" .. amz_date
    }, "\n") .. "\n"
    local canonical_request = sha256_digest(table.concat({
        method,
        url,
        query,
        canonical_headers,
        SIGNED_HEADERS,
        sha256_digest(body),
    }, "\n"))

    local string_to_sign = table.concat({ "AWS4-HMAC-SHA256", amz_date, credential_scope, canonical_request }, "\n")

    return resty_string.to_hex(sign(signing_key, string_to_sign))
end

function AWSAuth.aws_v4_signature(self, params)
    local aws_access_key = params.aws_access_key
    local region = params.region
    local service = params.service

    local timestamp = params.timestamp
    local date_stamp = os.date('!%Y%m%d', timestamp)
    local amz_date = os.date('!%Y%m%dT%H%M%SZ', timestamp)

    local credential = table.concat({ aws_access_key, date_stamp, region, service, 'aws4_request' }, "/")

    local authorization = table.concat({
        "AWS4-HMAC-SHA256 Credential=" .. credential,
        "SignedHeaders=" .. SIGNED_HEADERS,
        "Signature=" .. build_signature(params, date_stamp, amz_date)
    }, ", ")

    return {
        authorization = authorization,
        amz_date = amz_date,
    }
end

return AWSAuth
