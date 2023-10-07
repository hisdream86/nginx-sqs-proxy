local aws_auth = require("aws_auth")

local aws_region = os.getenv("AWS_REGION")
local account_id = os.getenv("AWS_ACCOUNT_ID")
local queue_name = os.getenv("QUEUE_NAME")

ERROR_TEXT_SERVER_ERROR = "An internal server error occurred."


local function send_error_response(status, message)
    ngx.status = status
    ngx.header.content_type = "application/json"
    ngx.print("{\"message\":\"" .. message .. "\"}")
    return ngx.exit(ngx.status)
end

local function send_response(status, data)
    ngx.status = status
    ngx.header.content_type = "application/json"
    ngx.print(data)
    return ngx.exit(ngx.status)
end

local function authentications()
    local authenticated, status, data = nil, nil, nil

    local ok, response = pcall(ngx.location.capture, "/authentications", {
        method = ngx.HTTP_POST }
    )

    if not ok then
        return nil, "Fail to request an authentication" .. response
    end

    if response.status == ngx.HTTP_OK then
        authenticated = true
    else
        authenticated = false
        status = response.status
        data = response.body
    end

    return authenticated, nil, status, data
end

local function send_sqs_message(data)
    local request_data = table.concat({
        "Action=SendMessage",
        "MessageBody=" .. data,
        "Version=2012-11-05"
    }, "&")

    local host = "sqs." .. aws_region .. ".amazonaws.com"
    local queue_url = "/" .. account_id .. "/" .. queue_name .. "/"
    local access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
    local secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    local session_token = nil

    if access_key_id == nil or secret_access_key == nil then
        local credentials, err = aws_auth:get_aws_credentials()
        if not credentials then
            return false, "Fail to get credentials: " .. err
        end
        access_key_id = credentials.access_key_id
        secret_access_key = credentials.secret_access_key
        session_token = credentials.session_token
    end

    local auth = aws_auth:aws_v4_signature({
        aws_access_key = access_key_id,
        aws_access_secret = secret_access_key,
        region = aws_region,
        host = host,
        service = "sqs",
        content_type = "application/x-www-form-urlencoded",
        method = "POST",
        url = queue_url,
        body = request_data,
        timestamp = ngx.time(),
    })

    ngx.req.set_header("host", host)
    ngx.req.set_header("authorization", auth.authorization)
    ngx.req.set_header("x-amz-date", auth.amz_date)
    ngx.req.set_header("content-type", "application/x-www-form-urlencoded")

    if session_token then
        ngx.req.set_header("x-amz-security-token", session_token)
    end

    local ok, response = pcall(ngx.location.capture, "/sqs-proxy", {
        method = ngx.HTTP_POST,
        body = request_data
    })

    if not ok then
        return false, "Fail to request SQS API: " .. response
    end

    if response.status ~= ngx.HTTP_OK then
        return false, response.body .. " (" .. response.status .. ")"
    end

    return true, nil
end

local authenticated, err, auth_status, auth_message = authentications()

if err then
    ngx.log(ngx.ERR, "Fail to request an authentication: " .. err)
    return send_error_response(ngx.HTTP_INTERNAL_SERVER_ERROR, ERROR_TEXT_SERVER_ERROR)
end

if not authenticated then
    return send_response(auth_status, auth_message)
end

ngx.req.read_body()

local data = ngx.req.get_body_data()
if not data then
    return send_error_response(ngx.HTTP_BAD_REQUEST, "Request data is empty or exceeds size limits.")
end

local success, err = send_sqs_message(ngx.escape_uri(data))

if not success then
    ngx.log(ngx.ERR, "Fail to enqueue a message: " .. err)
    return send_error_response(ngx.HTTP_INTERNAL_SERVER_ERROR, ERROR_TEXT_SERVER_ERROR)
end

ngx.status = ngx.HTTP_OK
ngx.exit(ngx.status)
