module Zeek::UnauthorizedSMB;

export {
    redef enum Notice::Type += { UnauthorizedSMBAccess };

    const smb_allowed_ips: set[addr] = {
        192.168.1.10,
        192.168.1.11
    } &redef;

    type SMBLogEntry: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        user: string &log;
        msg: string &log;
    };

    redef enum Log::ID += { LOG };

    global log_smb: log_id = Log::create_stream(LOG, SMBLogEntry);
}

event smb1_session_setup(c: connection, user: string) {
    if ( c$id$resp_h !in smb_allowed_ips ) {
        local msg = fmt("Unauthorized SMB1 access to %s by %s", c$id$resp_h, user);
        Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id, $user=user, $msg=msg]);
        NOTICE([$note=UnauthorizedSMBAccess, $msg=msg, $conn=c]);
    }
}

event smb2_session_setup(c: connection, user: string) {
    if ( c$id$resp_h !in smb_allowed_ips ) {
        local msg = fmt("Unauthorized SMB2 access to %s by %s", c$id$resp_h, user);
        Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id, $user=user, $msg=msg]);
        NOTICE([$note=UnauthorizedSMBAccess, $msg=msg, $conn=c]);
    }
}
