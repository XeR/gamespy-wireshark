p_natneg = Proto("NatNeg", "GameSpy NAT Negotiation");

-------------------------------------------------------------------------------
-- InitPacket
--
-- typedef struct _InitPacket
-- {
-- 	unsigned char porttype;
-- 	unsigned char clientindex;
-- 	unsigned char usegameport;
-- 	unsigned int localip;
-- 	unsigned short localport;
-- } InitPacket;
--
-- strcpy(buffer + INITPACKET_SIZE, __GSIACGamename);
-------------------------------------------------------------------------------

enum_portType = {
	[0] = "GP",
	      "NN1",
	      "NN2",
	      "NN3",
}

iporttype = ProtoField.uint8  ("natneg.init.type",  "Port type", base.DEC, enum_portType)
iindex    = ProtoField.uint8  ("natneg.init.index", "Client index")
igameport = ProtoField.bool   ("natneg.init.usegp", "use game port")
iip       = ProtoField.ipv4   ("natneg.init.ip",    "Local IP")
iport     = ProtoField.uint16 ("natneg.init.port",  "Local port")
igame     = ProtoField.stringz("natneg.init.game",  "Game name")

function parse_init(buffer, packet, tree)
	if buffer:len() >= 1 then tree:add(iporttype, buffer(0, 1)) end
	if buffer:len() >= 2 then tree:add(iindex,    buffer(1, 1)) end
	if buffer:len() >= 3 then tree:add(igameport, buffer(2, 1)) end
	if buffer:len() >= 7 then tree:add(iip,       buffer(3, 4)) end
	if buffer:len() >= 9 then tree:add(iport,     buffer(7, 2)) end
	if buffer:len() >  9 then tree:add(igame,     buffer(9))    end
end

-------------------------------------------------------------------------------
-- ConnectPacket
--
-- typedef struct _ConnectPacket
-- {
-- 	unsigned int remoteIP;
-- 	unsigned short remotePort;
-- 	unsigned char gotyourdata;
-- 	unsigned char finished;
-- } ConnectPacket;
-------------------------------------------------------------------------------

cip       = ProtoField.ipv4  ("natneg.connect.ip",       "Remote IP")
cport     = ProtoField.uint16("natneg.connect.port",     "Remote port")
cdata     = ProtoField.uint8 ("natneg.connect.data",     "Got your data", base.HEX)
cfinished = ProtoField.uint8 ("natneg.connect.finished", "Finished",      base.DEC, {
	[0] = "NOERROR",
	      "DEADBEAT_PARTNER",
	      "INIT_PACKETS_TIMEDOUT",
})

function parse_connect(buffer, packet, tree)
	if buffer:len() >= 4 then tree:add(cip,       buffer(0, 4)) end
	if buffer:len() >= 6 then tree:add(cport,     buffer(4, 2)) end
	if buffer:len() >= 7 then tree:add(cdata,     buffer(6, 1)) end
	if buffer:len() >= 8 then tree:add(cfinished, buffer(7, 1)) end
end

-------------------------------------------------------------------------------
-- ReportPacket
--
-- typedef struct _ReportPacket
-- {
-- 	unsigned char porttype;
-- 	unsigned char clientindex;
-- 	unsigned char negResult;
-- 	NatType natType;
-- 	NatMappingScheme natMappingScheme;
-- 	char gamename[50];
-- } ReportPacket;
-------------------------------------------------------------------------------

enum_NatType = {
	[0] = "no_nat",
	      "firewall_only",
	      "full_cone",
	      "restricted_cone",
	      "port_restricted_cone",
	      "symmetric",
	      "unknown",
}

enum_NatMappingScheme = {
	[0] = "unrecognized",
	      "private_as_public",
	      "consistent_port",
	      "incremental",
	      "mixed",
}

rporttype = ProtoField.uint8  ("natneg.report.type",   "Port type",          base.DEC, enum_portType)
rindex    = ProtoField.uint8  ("natneg.report.index",  "Client index")
rresult   = ProtoField.uint8  ("natneg.report.result", "Sever result")
rtype     = ProtoField.uint32 ("natneg.report.type",   "NAT Type",           base.DEC, enum_NatType)
rscheme   = ProtoField.uint32 ("natneg.report.scheme", "NAT mapping scheme", base.DEC, enum_NatMappingScheme)
rgame     = ProtoField.stringz("natneg.report.game",   "Game name")

function parse_report(buffer, packet, tree)
	if buffer:len() >=  1 then tree:add(rporttype, buffer(0, 1))   end
	if buffer:len() >=  2 then tree:add(rindex,    buffer(1, 1))   end
	if buffer:len() >=  3 then tree:add(rresult,   buffer(2, 1))   end
	if buffer:len() >=  7 then tree:add(rtype,     buffer(3, 4))   end
	if buffer:len() >= 11 then tree:add(rscheme,   buffer(7, 4))   end
	if buffer:len() >= 12 then tree:add(rgame,     buffer(11, 50)) end
end

-------------------------------------------------------------------------------
-- PreinitPacket
--
-- typedef struct _PreinitPacket
-- {
-- 	unsigned char clientindex;
-- 	unsigned char state;
-- 	int clientID;
-- } PreinitPacket;
-------------------------------------------------------------------------------

enum_pstate = {
	[0] = "WAITING_FOR_CLIENT",
	      "WAITING_FOR_MATCHUP",
	      "READY",
}

pindex = ProtoField.uint8 ("natneg.preinit.index", "Client index")
pid    = ProtoField.uint32("natneg.preinit.id",    "Client ID",     base.HEX)
pstate = ProtoField.uint8 ("natneg.preinit.state", "State",         base.DEC, enum_pstate)

function parse_preinit(buffer, packet, tree)
	if buffer:len() >= 1 then tree:add(pindex, buffer(0, 1)) end
	if buffer:len() >= 2 then tree:add(pstate, buffer(1, 1)) end
	if buffer:len() >= 6 then tree:add(pid,    buffer(2, 4)) end
end

-------------------------------------------------------------------------------
-- NatNegPacket
--
-- typedef struct _NatNegPacket {
-- 	// Base members:
-- 	unsigned char magic[NATNEG_MAGIC_LEN];
-- 	unsigned char version;
-- 	unsigned char packettype;
-- 	int cookie;
--
-- 	union
-- 	{
-- 		InitPacket Init;
-- 		ConnectPacket Connect;
-- 		ReportPacket Report;
-- 		PreinitPacket Preinit;
-- 	} Packet;
--
-- } NatNegPacket;
-------------------------------------------------------------------------------

enum_type = {
	[0]  = "INIT",
	[1]  = "INITACK",
	[2]  = "ERTTEST",
	[3]  = "ERTACK",
	[4]  = "STATEUPDATE",
	[5]  = "CONNECT",
	[6]  = "CONNECT_ACK",
	[7]  = "CONNECT_PING",
	[8]  = "BACKUP_TEST",
	[9]  = "BACKUP_ACK",
	[10] = "ADDRESS_CHECK",
	[11] = "ADDRESS_REPLY",
	[12] = "NATIFY_REQUEST",
	[13] = "REPORT",
	[14] = "REPORT_ACK",
	[15] = "PREINIT",
	[16] = "PREINIT_ACK",
}

magic      = ProtoField.bytes ("natneg.magic",   "magic number", base.NONE)
version    = ProtoField.uint8 ("natneg.version", "version",      base.DEC)
packettype = ProtoField.uint8 ("natneg.type",    "packet type",  base.DEC, enum_type)
cookie     = ProtoField.uint32("natneg.cookie",  "cookie",       base.HEX)

p_natneg.fields = {
	magic, version, packettype, cookie,                -- NatNeg
	iporttype, iindex, igameport, iip, iport, igame,   -- InitPacket
	cip, cport, cdata, cfinished,                      -- ConnectPacket
	rporttype, rindex, rresult, rtype, rscheme, rgame, -- Report
	pindex, pstate, pid,                               -- PreInit
};

function parse_natneg(buffer, packet, tree)
	-- Make sure we're dealing with a NAT Negotiation packet
	if buffer:len() < 12 then
		return false
	end
	
	if buffer(0, 6):bytes() ~= ByteArray.new("FD FC 1E 66 6A B2") then
		return false
	end

	local types = {
		[0]  = parse_init,    -- INIT
		[1]  = parse_init,    -- INITACK
		[2]  = parse_init,    -- ERTTEST
		[3]  = parse_init,    -- ERTACK
		[5]  = parse_connect, -- CONNECT
		[6]  = parse_init,    -- CONNECT_ACK
		[7]  = parse_connect, -- CONNECT_PING
		[11] = parse_init,    -- ADDRESS_REPLY
		[13] = parse_report,  -- REPORT
		[14] = parse_ack,     -- REPORT_ACK
		[15] = parse_preinit, -- PREINIT
		[16] = parse_ack,     -- PREINIT_ACK
	}

	local subtree = tree:add(p_natneg, buffer());

 	packet.cols.protocol = "NatNeg"
	packet.cols.info     = ""

	local ptype  = buffer(7, 1):uint()
	local cookie = buffer(8, 4):uint()

	subtree:add(magic,      buffer(0, 6))
	subtree:add(version,    buffer(6, 1))
	subtree:add(packettype, ptype)
	subtree:add(cookie,     cookie)

	if(enum_type[ptype] == nil) then
		packet.cols.info = "Unknown"
	else
		packet.cols.info = string.format("%s: %X", enum_type[ptype], cookie)
	end

	if(types[ptype] ~= nil) then
		types[ptype](buffer(12), packet, subtree)
	end

	return true
end

p_natneg:register_heuristic("udp", parse_natneg)