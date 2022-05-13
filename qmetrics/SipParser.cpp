//
// Created by Eytan on 10/20/2021.
//

#include "SipParser.h"
#include <cstring>
#include <list>
#include <map>
#include <memory>
#include <string>

#define SIP_METHOD_200_OK "200 OK"
#define SIP_METHOD_ACK "ACK"
#define SIP_METHOD_ACK_SIZE 3
#define SIP_METHOD_BYE "BYE"
#define SIP_METHOD_BYE_SIZE 3
#define SIP_METHOD_INVITE "INVITE"
#define SIP_METHOD_INVITE_SIZE 6
#define SIP_RESPONSE_200_OK "SIP/2.0 200"
#define SIP_RESPONSE_200_OK_SIZE 11
#define SIP_RESPONSE_SESSION_PROGRESS "SIP/2.0 183 Session Progress"
#define SIP_RESPONSE_SESSION_PROGRESS_SIZE 28

#define CURRENT_TIME 0
#define SIP_START 0
#define SIP_STOP 1

constexpr bool    m_ipFragmentsReassemble    = false, m_sipDetectSessionProgress = true, m_sipDropIndirectInvite = false, m_sipRequestUriAsLocalParty = true, m_sipTreat200OkAsInvite = false;
constexpr char    m_sipLocalPartyFieldName[] = "x-Local-Extension:", m_sipGroupPickUpPattern[] = "";
constexpr bool    m_dahdiIntercept           = false, m_rtpReportDtmf = false;
constexpr u_short PORT_NUMBER                = 5060;
const bool        m_sipReportFullAddress     = false;

class Sip200OkInfo {
public:
    Sip200OkInfo() {
        m_mediaIp.s_addr = 0;
        m_hasSdp = false;
    }

    std::string    m_callId;
    bool           m_hasSdp;
    struct in_addr m_mediaIp;
    std::string    m_mediaPort;

    struct in_addr m_senderIp;
    struct in_addr m_receiverIp;
    std::string    m_from;
    std::string    m_fromName;
    std::string    m_to;
};

class SipByeInfo {
public:
    SipByeInfo() {
        m_senderIp.s_addr   = 0;
        m_receiverIp.s_addr = 0;
    }

    std::string    m_callId;
    struct in_addr m_senderIp;
    struct in_addr m_receiverIp;
    std::string    m_from;
    std::string    m_to;
    std::string    m_fromDomain;
    std::string    m_toDomain;
    std::string    m_fromName;
    std::string    m_toName;
};

class SipInviteInfo {
public:
    SipInviteInfo() : m_telephoneEventPayloadType(0) {
        m_fromRtpIp.s_addr = 0;
        m_validated                     = false;
        m_attrSendonly                  = false;
        m_SipGroupPickUpPatternDetected = false;
        memset(m_orekaRtpPayloadTypeMap, 0, sizeof(m_orekaRtpPayloadTypeMap));
    }

    std::string                         m_sipMethod;
    struct in_addr                      m_senderIp;
    struct in_addr                      m_originalSenderIp;
    struct in_addr                      m_receiverIp;
    struct in_addr                      m_fromRtpIp;
    char                                m_senderMac[6];
    char                                m_receiverMac[6];
    std::string                         m_fromRtpPort;
    std::string                         m_from;
    std::string                         m_to;
    std::string                         m_callId;
    std::string                         m_replacesId;
    std::string                         m_requestUri;
    bool                                m_validated;        // true when an RTP stream has been seen for the INVITE
    bool                                m_attrSendonly;        // true if the SDP has a:sendonly
    std::map <std::string, std::string> m_extractedFields;
    int                                 m_telephoneEventPayloadType;
    std::string                         m_fromDomain;
    std::string                         m_toDomain;
    std::string                         m_fromName;
    std::string                         m_toName;
    std::string                         m_userAgent;
    std::string                         m_sipDialedNumber;
    std::string                         m_sipRemoteParty;
    std::string                         m_contact;
    std::string                         m_contactName;
    std::string                         m_contactDomain;
    bool                                m_SipGroupPickUpPatternDetected;
    //
    //  track dynamic RTP payload types present in SDP
    //  we need 32 bytes to track payload types 96-127.
    //  value is 0 if payload type is not in the SDP.
    //  otherwise it will be set to our internal RTP payload type
    unsigned char                       m_orekaRtpPayloadTypeMap[32];

    time_t m_recvTime;
};

#define INADDRSZ         4

int inet_pton4(const char *src, struct in_addr *dstAddr) {
    auto              dst      = (unsigned char *) dstAddr;
    static const char digits[] = "0123456789";
    int               saw_digit, octets, ch;
    unsigned char     tmp[INADDRSZ], *tp;

    saw_digit = 0;
    octets    = 0;
    tp        = tmp;
    *tp = 0;
    while ((ch = *src++) != '\0') {
        const char *pch;

        if ((pch = strchr(digits, ch)) != nullptr) {
            unsigned int val = *tp * 10 + (unsigned int) (pch - digits);

            if (val > 255)
                return 0;
            *tp = (unsigned char) val;
            if (!saw_digit) {
                if (++octets > 4)
                    return 0;
                saw_digit = 1;
            }
        }
        else if (ch == '.' && saw_digit) {
            if (octets == 4)
                return 0;
            *++tp = 0;
            saw_digit = 0;
        }
        else
            return 0;
    }
    if (octets < 4)
        return 0;
    /* bcopy(tmp, dst, INADDRSZ); */
    memcpy(dst, tmp, INADDRSZ);
    return 1;
}

char *memFindEOL(char *start, const char *limit) {
    char *c = start;
    while (*c != '\r' && *c != '\n' && c < limit) {
        ++c;
    }
    if (*c == '\r' || *c == '\n') {
        return c;
    }
    return start;
}

const char *memFindStr(const char *toFind, const char *start, const char *stop) {
    for (const char *ptr = start; (ptr < stop) && (ptr != nullptr); ptr = (char *) memchr(ptr + 1, toFind[0], (stop - ptr - 1))) {
        if (strncasecmp(toFind, ptr, ((int) strlen(toFind) > (stop - ptr) ? (stop - ptr) : strlen(toFind))) == 0) {
            return ptr;
        }
    }
    return nullptr;
}

char *SkipWhitespaces(char *in, const char *limit) {
    char *c = in;
    while (*c == 0x20 && c < limit) {
        ++c;
    }
    return c;
}

char *GrabLine(char *start, const char *limit, std::string &out) {
    char *c = start;
    while (c < limit && *c != 0x0D && *c != 0x0A) {
        out += *c++;
    }
    return c;
}

inline std::string GrabLineSkipLeadingWhitespace(char *start, const char *limit) {
    std::string res;
    GrabLine(SkipWhitespaces(start, limit), limit, res);
    return res;
}

std::string GrabSipUriDomain(char *in, const char *limit) {
    char *userStart = SkipWhitespaces(in, limit);
    if (userStart >= limit) {
        return {};
    }

    char *domainStart = strchr(userStart, '@');
    if (!domainStart) {
        return {};
    }

    domainStart += 1;
    if (*domainStart == '\0' || domainStart >= limit) {
        return {};
    }

    std::string res = {};
    for (char   *c  = domainStart; (isalnum(*c) || *c == '.' || *c == '-' || *c == '_') && (c < limit); c = c + 1) {
        res += *c;
    }
    return res;
}

std::string GrabSipName(char *in, const char *limit) {
    char       *nameStart = SkipWhitespaces(in, limit);
    const char *nameEnd   = memFindStr("<sip:", nameStart, limit);

    if (nameStart >= limit || nameEnd == nullptr || nameEnd <= nameStart) {
        return {};
    }

    // Get all characters before the <sip:
    std::string res = {};
    for (char   *c  = nameStart; c < nameEnd; ++c) {
        if (c == nameStart && *c == '"') {
            continue;
        }
        if ((c + 2 == nameEnd || c + 1 == nameEnd) && *c == '"') {
            break;
        }
        if (c + 1 == nameEnd && *c == ' ') {
            break;
        }
        res += *c;
    }
    return res;
}

std::string GrabSipUriUser(char *in, const char *limit) {
    char *userStart = SkipWhitespaces(in, limit);
    if (userStart >= limit) {
        return {};
    }

    // What stops a SIP URI user is a ':' (separating user from pwd) or an '@' (separating user from hostname)
    // but no need to test for these as we only allow alphanums and a few other chars
    std::string res = {};
    for (char   *c  = userStart;
         (isalnum(*c) || *c == '#' || *c == '*' || *c == '.' || *c == '+' || *c == '-' || *c == '_' || *c == '%') && c < limit; c = c + 1) {
        res += *c;
    }
    return res;
}

std::string GrabSipUserAddress(char *in, const char *limit) {
    char *userStart     = SkipWhitespaces(in, limit);
    bool passedUserPart = false;

    if (userStart >= limit) {
        return {};
    }

    /* Taken from RFC 1035, section 2.3.1 recommendation for
     * domain names, we will add checks for '.' and '@' to allow
     * the host part */
    std::string res = {};
    for (char   *c  = userStart;
         (isalnum(*c) || *c == '#' || *c == '*' || *c == '.' || *c == '+' || *c == '-' || *c == '_' || *c == ':' || *c == '@') && c < limit; c = c + 1) {
        if (*c == '@' && !passedUserPart) {
            passedUserPart = true;
        }

        if (*c == ':' && passedUserPart) {
            break;
        }

        res += *c;
    }
    return res;
}

std::string GrabToken(const char *in, const char *limit) {
    std::string     res = {};
    for (const char *c  = in; *c != '\0' && *c != 0x20 && *c != 0x0D && *c != 0x0A && c < limit; ++c) {
        res += *c;
    }
    return res;
}

std::string GrabTokenAcceptSpace(const char *in, const char *limit) {
    std::string     res = {};
    for (const char *c  = in; *c != '\0' && *c != 0x0D && *c != 0x0A && c < limit; ++c) {
        res += *c;
    }
    return res;
}

inline std::string GrabTokenSkipLeadingWhitespaces(char *in, const char *limit) {
    return GrabToken(SkipWhitespaces(in, limit), limit);
}

char *memFindAfter(const char *toFind, char *start, const char *stop) {
    for (char *ptr = start; (ptr < stop) && (ptr != nullptr); ptr = (char *) memchr(ptr + 1, toFind[0], (stop - ptr - 1))) {
        if (strncasecmp(toFind, ptr, strlen(toFind)) == 0) {
            return ptr + strlen(toFind);
        }
    }
    return nullptr;
}

void GetDynamicPayloadMapping(const char *start, const char *stop, unsigned char *map) {
    std::string rtpmap = "a=rtpmap:";
    const char  *rtpmapPos;
    rtpmapPos = memFindStr(rtpmap.c_str(), start, stop);
    while (rtpmapPos != nullptr) {
        int         plType   = -1;
        std::string fullLine = GrabTokenAcceptSpace(rtpmapPos, stop);
        std::string plStr    = GrabToken(rtpmapPos + rtpmap.length(), stop);
        if (plStr.length() > 0) {
            plType = std::stoi(plStr);
        }
        /*if (plType > 95 && plType < 127) {
            int orekaPayloadType = GetOrekaRtpPayloadTypeForSdpRtpMap(fullLine);
            if (orekaPayloadType && orekaPayloadType != map[plType - 96]) {
                map[plType - 96] = orekaPayloadType; //remaps payload type to internal value
            }
        }*/

        rtpmapPos = memFindStr(rtpmap.c_str(), rtpmapPos + fullLine.length(), stop);
    }
}

void write_sip_event(const std::string &caller, const std::string &callee, const std::string &session_id, uint64_t eventTime, u_char eventType) {
    if (caller.empty() && callee == "anonymous@anonymous.invalid") {
        return;
    }
    printf("SIP %s: %s->%s\n", eventType == SIP_START ? "SIP_START" : "SIP_STOP", caller.c_str(), callee.c_str());
}

void SipParser::handle(EthernetHeaderStruct *ethernetHeader, IpHeaderStruct *ipHeader, int ipHeaderLength, u_char *ipPacketEnd) {
    auto udpHeader = (UdpHeaderStruct *) ((char *) ipHeader + ipHeaderLength);

    if (ntohs(udpHeader->source) != PORT_NUMBER && ntohs(udpHeader->dest) != PORT_NUMBER) {
        return;
    }

    u_char *udpPayload = (u_char *) udpHeader + sizeof(UdpHeaderStruct);

    if (TrySipInvite(ethernetHeader, ipHeader, udpHeader, udpPayload, ipPacketEnd)) {
        printf("invite\n");
    }
    else if (TrySip200Ok(ethernetHeader, ipHeader, udpHeader, udpPayload, ipPacketEnd)) {
        printf("200\n");
    }
    else if (TrySipBye(ethernetHeader, ipHeader, udpHeader, udpPayload, ipPacketEnd)) {
        printf("bye\n");
    }
}

bool SipParser::TrySip200Ok(EthernetHeaderStruct *ethernetHeader, IpHeaderStruct *ipHeader, UdpHeaderStruct *udpHeader, u_char *udpPayload, u_char *packetEnd) {
    bool result = false;

    if (m_sipTreat200OkAsInvite) {
        return false;
    }

    printf("Calling elvis 0x2\n");


    int  sipLength = ntohs(udpHeader->len) - sizeof(UdpHeaderStruct);
    char *sipEnd   = (char *) udpPayload + sipLength;
    if (sipLength < SIP_RESPONSE_200_OK_SIZE || sipEnd > (char *) packetEnd) {
        printf("Calling elvis 0x3\n");

        ;    // packet too short
    }
    else if (memcmp(SIP_RESPONSE_200_OK, (void *) udpPayload, SIP_RESPONSE_200_OK_SIZE) == 0) {
        printf("Calling elvis 0x4\n");


        result = true;

        std::shared_ptr <Sip200OkInfo> info = std::make_shared<Sip200OkInfo>();

        char *fromField = memFindAfter("From:", (char *) udpPayload, sipEnd);
        if (!fromField) {
            fromField = memFindAfter("\nf:", (char *) udpPayload, sipEnd);
        }
        char *toField = memFindAfter("To:", (char *) udpPayload, sipEnd);
        if (!toField) {
            toField = memFindAfter("\nt:", (char *) udpPayload, sipEnd);
        }

        char *callIdField = memFindAfter("Call-ID:", (char *) udpPayload, sipEnd);
        if (!callIdField) {
            callIdField = memFindAfter("\ni:", (char *) udpPayload, sipEnd);
        }

        char *audioField             = nullptr;
        char *connectionAddressField = nullptr;

        if (callIdField) {
            info->m_callId = GrabTokenSkipLeadingWhitespaces(callIdField, sipEnd);
            audioField             = memFindAfter("m=audio ", callIdField, sipEnd);
            connectionAddressField = memFindAfter("c=IN IP4 ", callIdField, sipEnd);
        }
        if (audioField && connectionAddressField) {
            info->m_hasSdp = true;

            info->m_mediaPort = GrabToken(audioField, sipEnd);

            std::string    connectionAddress = GrabToken(connectionAddressField, sipEnd);
            struct in_addr mediaIp           = {};
            if (!connectionAddress.empty() && inet_pton4(connectionAddress.c_str(), &mediaIp)) {
                info->m_mediaIp = mediaIp;
            }
        }

        if (fromField) {
            char *fromFieldEnd = memFindEOL(fromField, sipEnd);
            info->m_fromName = GrabSipName(fromField, fromFieldEnd);

            char *sipUser = memFindAfter("sip:", fromField, fromFieldEnd);
            char *field   = sipUser ? sipUser : fromField;
            info->m_from = m_sipReportFullAddress ? GrabSipUserAddress(field, fromFieldEnd) : GrabSipUriUser(field, fromFieldEnd);
        }
        if (toField) {
            std::string to;
            char        *toFieldEnd = GrabLine(toField, sipEnd, to);
            printf("to: %s\n", to.c_str());

            char *sipUser = memFindAfter("sip:", toField, toFieldEnd);
            char *field   = sipUser ? sipUser : toField;
            info->m_to = m_sipReportFullAddress ? GrabSipUserAddress(field, toFieldEnd) : GrabSipUriUser(field, toFieldEnd);
        }
        info->m_senderIp             = ipHeader->ip_src;
        info->m_receiverIp           = ipHeader->ip_dest;

        //printf("..200 OK: %s\n", info->ToString().c_str());

        //VoIpSessionsSingleton::instance()->ReportSip200Ok(info);

        write_sip_event(info->m_fromName, info->m_to, info->m_callId, CURRENT_TIME, SIP_START);
    }

    printf("Calling elvis 0x5\n");


    return result;
}

bool SipParser::TrySipBye(EthernetHeaderStruct *ethernetHeader, IpHeaderStruct *ipHeader, UdpHeaderStruct *udpHeader, u_char *udpPayload, u_char *packetEnd) {
    bool result = false;

    int  sipLength = ntohs(udpHeader->len) - sizeof(UdpHeaderStruct);
    char *sipEnd   = (char *) udpPayload + sipLength;
    if (sipLength < (int) sizeof(SIP_METHOD_BYE) || sipEnd > (char *) packetEnd) {
        return false;
    }

    if (memcmp(SIP_METHOD_BYE, (void *) udpPayload, SIP_METHOD_BYE_SIZE) == 0) {
        result = true;
        std::shared_ptr <SipByeInfo> info = std::make_shared<SipByeInfo>();

        char *fromField = memFindAfter("From:", (char *) udpPayload, sipEnd);
        if (!fromField) {
            fromField = memFindAfter("\nf:", (char *) udpPayload, sipEnd);
        }
        char *toField = memFindAfter("To:", (char *) udpPayload, sipEnd);
        if (!toField) {
            toField = memFindAfter("\nt:", (char *) udpPayload, sipEnd);
        }

        char *callIdField = memFindAfter("Call-ID:", (char *) udpPayload, sipEnd);
        if (!callIdField) {
            callIdField = memFindAfter("\ni:", (char *) udpPayload, sipEnd);
        }
        if (callIdField) {
            info->m_callId = GrabTokenSkipLeadingWhitespaces(callIdField, sipEnd);
        }

        if (fromField) {
            char *fromFieldEnd = memFindEOL(fromField, sipEnd);

            info->m_fromName = GrabSipName(fromField, fromFieldEnd);

            char *sipUser = memFindAfter("sip:", fromField, fromFieldEnd);
            char *field   = sipUser ? sipUser : fromField;
            info->m_from       = m_sipReportFullAddress ? GrabSipUserAddress(sipUser, fromFieldEnd) : GrabSipUriUser(sipUser, fromFieldEnd);
            info->m_fromDomain = GrabSipUriDomain(fromField, fromFieldEnd);
        }
        if (toField) {
            std::string to;
            char        *toFieldEnd = GrabLine(toField, sipEnd, to);
            printf("to: %s\n", to.c_str());

            info->m_toName = GrabSipName(toField, toFieldEnd);

            char *sipUser = memFindAfter("sip:", toField, toFieldEnd);
            char *field   = sipUser ? sipUser : toField;
            info->m_to       = m_sipReportFullAddress ? GrabSipUserAddress(field, toFieldEnd) : GrabSipUriUser(field, toFieldEnd);
            info->m_toDomain = GrabSipUriDomain(field, toFieldEnd);
        }

        info->m_senderIp   = ipHeader->ip_src;
        info->m_receiverIp = ipHeader->ip_dest;

        //printf("BYE: %s\n", info->ToString().c_str());

        std::string from = info->m_from.empty() ? info->m_fromName : info->m_from;
        write_sip_event(info->m_fromName, info->m_to, info->m_callId, CURRENT_TIME, SIP_STOP);
    }
    return result;
}

bool SipParser::TrySipInvite(EthernetHeaderStruct *ethernetHeader, IpHeaderStruct *ipHeader, UdpHeaderStruct *udpHeader, u_char *udpPayload, u_char *packetEnd) {
    bool        result = false;
    bool        drop   = false;
    std::string sipMethod;

    int  sipLength = ntohs(udpHeader->len) - sizeof(UdpHeaderStruct);
    char *sipEnd   = (char *) udpPayload + sipLength;

    if (!m_ipFragmentsReassemble && sipEnd > (char *) packetEnd && ipHeader->offset() == 0) {
        sipEnd = (char *) packetEnd;
    }

    if (sipLength < 3 || sipEnd > (char *) packetEnd) {
        drop = true;    // packet too short
    }
    else if (memcmp(SIP_METHOD_INVITE, (void *) udpPayload, SIP_METHOD_INVITE_SIZE) == 0) {
        sipMethod = SIP_METHOD_INVITE;
    }
    else if (memcmp(SIP_METHOD_ACK, (void *) udpPayload, SIP_METHOD_ACK_SIZE) == 0) {
        sipMethod = SIP_METHOD_ACK;
    }
    else if (!m_sipTreat200OkAsInvite && (memcmp(SIP_RESPONSE_200_OK, (void *) udpPayload, SIP_RESPONSE_200_OK_SIZE) == 0)) {
        sipMethod = SIP_METHOD_200_OK;
        printf("TrySipInvite: packet matches 200 OK and SipTreat200OkAsInvite is enabled\n");
    }
    else if (!m_sipDetectSessionProgress && (memcmp(SIP_RESPONSE_SESSION_PROGRESS, (void *) udpPayload, SIP_RESPONSE_SESSION_PROGRESS_SIZE) == 0)) {
        sipMethod = SIP_RESPONSE_SESSION_PROGRESS;
    }
    else {
        drop = true;
    }

    if (!drop) {
        //Drop invite for SRTP Sessions
        if (nullptr != memFindAfter("fingerprint:", (char *) udpPayload, sipEnd)) {
            printf("TrySipInvite: Don't parse secure sessions\n");
            drop = true;
        }
    }

    if (!drop) {
        result = true;

        std::shared_ptr <SipInviteInfo> info = std::make_shared<SipInviteInfo>();
        info->m_sipMethod = sipMethod;
        char *fromField = memFindAfter("From:", (char *) udpPayload, sipEnd);
        if (!fromField) {
            fromField = memFindAfter("\nf:", (char *) udpPayload, sipEnd);
        }
        char *toField = memFindAfter("To:", (char *) udpPayload, sipEnd);
        if (!toField) {
            toField = memFindAfter("\nt:", (char *) udpPayload, sipEnd);
        }
        char *callIdField = memFindAfter("Call-ID:", (char *) udpPayload, sipEnd);
        if (!callIdField) {
            callIdField = memFindAfter("\ni:", (char *) udpPayload, sipEnd);
        }

        char *replacesField = memFindAfter("Replaces:", (char *) udpPayload, sipEnd);
        if (!replacesField) {
            replacesField = memFindAfter("\nr:", (char *) udpPayload, sipEnd);
        }

        char *contactField = memFindAfter("Contact:", (char *) udpPayload, sipEnd);
        if (!contactField) {
            contactField = memFindAfter("\nc:", (char *) udpPayload, sipEnd);
        }

        char *audioSdpStart = (char *) udpPayload;
        char *audioSdpEnd   = (char *) sipEnd;

        char *audioStart = memFindAfter("m=audio", (char *) udpPayload, sipEnd);
        char *videoStart = memFindAfter("m=video", (char *) udpPayload, sipEnd);

        if (audioStart < videoStart) {
            audioSdpEnd = videoStart;
        }

        if (audioStart > videoStart) {
            audioSdpStart = audioStart;
        }

        char *localExtensionField    = memFindAfter(m_sipLocalPartyFieldName, (char *) udpPayload, sipEnd);
        char *audioField             = nullptr;
        char *connectionAddressField = nullptr;

        char            *attribSendonly  = memFindAfter("a=sendonly", (char *) audioSdpStart, audioSdpEnd);
        char            *attribInactive  = memFindAfter("a=inactive", (char *) audioSdpStart, audioSdpEnd);
        char            *rtpmapAttribute = memFindAfter("\na=rtpmap:", (char *) audioSdpStart, audioSdpEnd);
        char            *userAgentField  = memFindAfter("\nUser-Agent:", (char *) udpPayload, sipEnd);

        if (!m_sipRequestUriAsLocalParty) {
            char *sipUriAttribute = memFindAfter("INVITE ", (char *) udpPayload, sipEnd);

            if (sipUriAttribute) {
                char *sipUriAttributeEnd = memFindEOL(sipUriAttribute, sipEnd);
                char *sipUser            = memFindAfter("sip:", sipUriAttribute, sipUriAttributeEnd);
                char *field              = sipUser ? sipUser : sipUriAttribute;
                info->m_requestUri = m_sipReportFullAddress ? GrabSipUserAddress(field, sipUriAttributeEnd) : GrabSipUriUser(field, sipUriAttributeEnd);
            }
        }

        if (fromField) {

            char *fromFieldEnd = memFindEOL(fromField, sipEnd);

            info->m_fromName = GrabSipName(fromField, fromFieldEnd);

            char *sipUser = memFindAfter("sip:", fromField, fromFieldEnd);
            char *field   = sipUser ? sipUser : fromField;
            info->m_from       = m_sipReportFullAddress ? GrabSipUserAddress(field, fromFieldEnd) : GrabSipUriUser(field, fromFieldEnd);
            info->m_fromDomain = GrabSipUriDomain(field, fromFieldEnd);
        }
        if (toField) {
            std::string to;
            char        *toFieldEnd = GrabLine(toField, sipEnd, to);
            //printf("..to: %s\n", to.c_str());

            info->m_toName = GrabSipName(toField, toFieldEnd);

            char *sipUser = memFindAfter("sip:", toField, toFieldEnd);
            if (!sipUser) {
                sipUser = memFindAfter("tel:", toField, toFieldEnd);
            }
            char *field = sipUser ? sipUser : toField;
            info->m_to       = m_sipReportFullAddress ? GrabSipUserAddress(field, toFieldEnd) : GrabSipUriUser(field, toFieldEnd);
            info->m_toDomain = GrabSipUriDomain(field, toFieldEnd);

            if (info->m_to == m_sipGroupPickUpPattern) {
                info->m_SipGroupPickUpPatternDetected = true;
            }
        }
        if (callIdField) {
            info->m_callId = GrabTokenSkipLeadingWhitespaces(callIdField, sipEnd);
            audioField             = memFindAfter("m=audio ", callIdField, sipEnd);
            connectionAddressField = memFindAfter("c=IN IP4 ", callIdField, sipEnd);
        }
        if (replacesField) {
            std::string fieldContent  = GrabTokenSkipLeadingWhitespaces(replacesField, sipEnd);
            int         firstsemicoma = fieldContent.find(';');
            if (firstsemicoma != -1) {
                info->m_replacesId = fieldContent.substr(0, firstsemicoma);
            }
        }
        if (localExtensionField) {
            std::string localExtension = GrabTokenSkipLeadingWhitespaces(localExtensionField, sipEnd);
            if (!localExtension.empty()) {
                info->m_from = localExtension;
            }
        }
        if (userAgentField) {
            info->m_userAgent = GrabTokenSkipLeadingWhitespaces(userAgentField, sipEnd);
        }
        if (audioField) {
            info->m_fromRtpPort = GrabToken(audioField, sipEnd);
        }
        if (attribSendonly || attribInactive) {
            info->m_attrSendonly = true;
        }
        if (connectionAddressField) {
            std::string    connectionAddress = GrabToken(connectionAddressField, sipEnd);
            struct in_addr fromIp            = {};
            if (!connectionAddress.empty()) {
                if (inet_pton4(connectionAddress.c_str(), &fromIp)) {
                    info->m_fromRtpIp = fromIp;

                    if (m_sipDropIndirectInvite) {
                        if ((unsigned int) fromIp.s_addr != (unsigned int) ipHeader->ip_src.s_addr) {
                            // SIP invite SDP connection address does not match with SIP packet origin
                            drop = true;
                        }
                    }
                }
            }
        }
        if (contactField && sipMethod == SIP_METHOD_INVITE) {
            std::string contact;
            char        *contactFieldEnd = GrabLine(contactField, sipEnd, contact);

            info->m_contactName = GrabSipName(contactField, contactFieldEnd);

            char *sipUser = memFindAfter("sip:", contactField, contactFieldEnd);
            char *field   = sipUser ? sipUser : contactField;
            info->m_contact       = m_sipReportFullAddress ? GrabSipUserAddress(field, contactFieldEnd) : GrabSipUriUser(field, contactFieldEnd);
            info->m_contactDomain = GrabSipUriDomain(field, contactFieldEnd);
        }
        // SIP fields extraction
        for (const auto &it: {"X-record"}) {
            std::string fieldName = it + ':';
            char        *szField  = memFindAfter(fieldName.c_str(), (char *) udpPayload, sipEnd);
            if (szField) {
                info->m_extractedFields.insert(std::make_pair(it, GrabLineSkipLeadingWhitespace(szField, sipEnd)));
            }
        }

        if (m_rtpReportDtmf) {
            if (rtpmapAttribute) {
                std::string rtpPayloadType, nextToken;
                char        *nextStep = nullptr;

                while (rtpmapAttribute && rtpmapAttribute < sipEnd) {
                    rtpPayloadType = GrabTokenSkipLeadingWhitespaces(rtpmapAttribute, audioSdpEnd);
                    nextToken      = rtpPayloadType + ' ';
                    nextStep       = memFindAfter(nextToken.c_str(), rtpmapAttribute, audioSdpEnd);

                    /* We need our "nextStep" to contain at least the length
                     * of the string "telephone-event", 15 characters */
                    if (nextStep && ((sipEnd - nextStep) >= 15)) {
                        if (strncasecmp(nextStep, "telephone-event", 15) == 0) {
                            /* Our DTMF packets are indicated using * the payload type rtpPayloadType */
                            info->m_telephoneEventPayloadType = std::stoi(rtpPayloadType);
                            break;
                        }
                    }

                    rtpmapAttribute = memFindAfter("\na=rtpmap:", rtpmapAttribute, audioSdpEnd);
                }
            }
        }

        rtpmapAttribute          = memFindAfter("\na=rtpmap:", (char *) audioSdpStart, audioSdpEnd);
        if (rtpmapAttribute) {
            GetDynamicPayloadMapping(audioSdpStart, audioSdpEnd, info->m_orekaRtpPayloadTypeMap);
        }

        if ((unsigned int) info->m_fromRtpIp.s_addr == 0) {
            // In case connection address could not be extracted, use SIP invite sender IP address
            if (!m_dahdiIntercept) {
                info->m_fromRtpIp = ipHeader->ip_dest;
            }
            else {
                info->m_fromRtpIp = ipHeader->ip_src;
            }
        }
        if (sipMethod == SIP_METHOD_200_OK) {
            info->m_senderIp   = ipHeader->ip_dest;
            info->m_receiverIp = ipHeader->ip_src;
        }
        else {
            info->m_senderIp   = ipHeader->ip_src;
            info->m_receiverIp = ipHeader->ip_dest;
        }
        info->m_originalSenderIp = ipHeader->ip_src;
        info->m_recvTime         = time(nullptr);
        memcpy(info->m_senderMac, ethernetHeader->sourceMac, sizeof(info->m_senderMac));
        memcpy(info->m_receiverMac, ethernetHeader->destinationMac, sizeof(info->m_receiverMac));

        //printf("method:%s drop:%i m_fromRtpPort:%s m_from:%s m_to:%s m_callId:%s\n", sipMethod.c_str(), drop, info->m_fromRtpPort.c_str(), info->m_from.c_str(), info->m_to.c_str(), info->m_callId.c_str());

        if (sipMethod == SIP_METHOD_INVITE || !info->m_fromRtpPort.empty()) {
            // Only log SIP non-INVITE messages that contain SDP (i.e. with a valid RTP port)
            //printf("SIP_METHOD_INVITE: %i || %i\n", sipMethod == SIP_METHOD_INVITE, !info->m_fromRtpPort.empty());
        }

        //Sip INVITE without sdp will be reported, but other methods without sdp will not be
        if (!drop && sipMethod == SIP_METHOD_INVITE && !info->m_from.empty() && !info->m_to.empty() && !info->m_callId.empty()) {
            //printf("SIP_METHOD_INVITE: %i && %i && %i\n", !info->m_from.empty(), !info->m_to.empty(), !info->m_callId.empty());
            //VoIpSessionsSingleton::instance()->ReportSipInvite(info);
            write_sip_event(info->m_from, info->m_to, info->m_callId, CURRENT_TIME, SIP_START);
        }
        else if (!drop && !info->m_fromRtpPort.empty() && !info->m_from.empty() && !info->m_to.empty() && !info->m_callId.empty()) {
            if (sipMethod == SIP_METHOD_200_OK) {

                /*
                std::string call_start_json = "{";
                call_start_json += "\"session_id\":\"" + info->m_callId + "\",\n";
                call_start_json += "\"direction\": 1,\n";
                call_start_json += "\"phone_number_from\":\"" + info->m_from + "\",\n";
                call_start_json += "\"phone_number_to\":\"" + info->m_to + "\",\n";
                call_start_json += "\"start\":" + std::string(std::to_string(current_time).c_str()) + " \n}";
                */

                printf("Calling elvis\n");
                write_sip_event(info->m_from, info->m_to, info->m_callId, CURRENT_TIME, SIP_START);
            }

            //VoIpSessionsSingleton::instance()->ReportSipInvite(info);
        }
    }
    return result;
}