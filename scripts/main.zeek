##! Zeek script is used to detect HTTP basic authentication servers.

module HTTPBasicAuth;

export {
          redef enum Notice::Type += {
                  ## Generated if a site is detected using Basic Access Authentication
                  Found
          };
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
        # This is a processing efficiency tactic here. Return early from the event.
        if(!Site::is_local_addr(c$id$resp_h) && HTTP::check_only_local_net==T) {
            return;
        }

        # local domain = (c?$http && c$http?$host) ? c$http$host : "--";
        # Check for field existence and assign defaults
        local username = c$http?$username ? c$http$username : "<unknown>";
        local password = c$http?$password ? c$http$password : "<unknown>";
        local respHost = c$http?$host ? c$http$host : cat(c$id$resp_h);
        local uri = c$http?$uri ? c$http$uri : "<unknown>";

        if (/AUTHORIZATION/ in name && /Basic/ in value)
        {
                # local parts: string_vec;
                # parts = split_string1(decode_base64(sub_bytes(value, 7, |value|)), /:/);
                # parts = split_string1(decode_base64(value), /:/);

                NOTICE([$note=Found,
                     $msg="A server using HTTP Basic authentication was detected",
                     $sub=fmt("%s%s (username: %s, password: %s)", respHost, uri, username, HTTP::default_capture_password == F ? "<blocked>" : password),
                     $identifier=cat(c$id$resp_h, c$id$resp_p),
                     $suppress_for=1day,
                     $conn=c]);
        }
}
