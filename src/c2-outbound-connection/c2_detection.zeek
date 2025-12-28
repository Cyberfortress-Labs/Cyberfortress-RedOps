# ============================================================================
# CYBERFORTRESS REDOPS - Zeek Script for C2 Detection (Connection-based)
# ============================================================================
# Detects C2 based on CONNECTION patterns (not payload)
# Works even when C2 server doesn't respond!
#
# Installation:
#   1. Copy to: /opt/zeek/share/zeek/site/c2_detection.zeek
#   2. Add to local.zeek: @load ./c2_detection.zeek
#   3. Deploy: zeekctl deploy
# ============================================================================

@load base/frameworks/notice

module C2Detection;

export {
    redef enum Notice::Type += {
        C2_Connection_Attempt,
        C2_Suspicious_Port,
        C2_Beacon_Detected,
    };
    
    # Known C2 IPs - add your IOCs here
    const c2_ips: set[addr] = {
        147.185.133.114,
        101.53.243.9,
    } &redef;
    
    # Suspicious C2 ports
    const c2_ports: set[port] = {
        4444/tcp,   # Metasploit
        5555/tcp,   # Common C2
        8443/tcp,   # Empire
    } &redef;
}

# Detect connection attempts to known C2 IPs
event connection_attempt(c: connection)
{
    local dst = c$id$resp_h;
    local dst_port = c$id$resp_p;
    local src = c$id$orig_h;
    
    # Check if destination is a known C2 IP
    if ( dst in c2_ips )
    {
        NOTICE([
            $note = C2_Connection_Attempt,
            $conn = c,
            $msg = fmt("Connection attempt to known C2 IP: %s:%s", dst, dst_port),
            $sub = fmt("Source: %s", src),
            $src = src,
            $dst = dst,
            $p = dst_port,
            $identifier = cat(src, dst)
        ]);
    }
    
    # Check if destination port is a known C2 port
    if ( dst_port in c2_ports )
    {
        NOTICE([
            $note = C2_Suspicious_Port,
            $conn = c,
            $msg = fmt("Connection to suspicious C2 port: %s:%s", dst, dst_port),
            $sub = fmt("Source: %s", src),
            $src = src,
            $dst = dst,
            $p = dst_port,
            $identifier = cat(src, dst, dst_port)
        ]);
    }
}

# Also detect on connection_state_remove (catches all connection states)
event connection_state_remove(c: connection)
{
    local dst = c$id$resp_h;
    local dst_port = c$id$resp_p;
    local src = c$id$orig_h;
    
    # Check C2 IPs (catches S0, REJ, etc.)
    if ( dst in c2_ips )
    {
        NOTICE([
            $note = C2_Connection_Attempt,
            $conn = c,
            $msg = fmt("C2 Connection Detected: %s -> %s:%s (state: %s)", src, dst, dst_port, c$conn$conn_state),
            $sub = fmt("Connection state: %s", c$conn$conn_state),
            $src = src,
            $dst = dst,
            $p = dst_port,
            $identifier = cat(src, dst, "state_remove")
        ]);
    }
}
