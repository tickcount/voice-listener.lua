-- LISTENER [v:0101110]
local is_syncing = false
local lifetime = 120
local last_verification = 0
local debugging_privelege_level = 0
local voice_callback = events.voice_message

-- ConVars
local voice_modenable = cvar.voice_modenable

local cl_mute_enemy_team = cvar.cl_mute_enemy_team
local cl_mute_all_but_friends_and_party = cvar.cl_mute_all_but_friends_and_party
local cl_mute_player_after_reporting_abuse = cvar.cl_mute_player_after_reporting_abuse

local last_availability_chk = 0
local last_voice_enabled = 1

cvar.voice_buffer_debug:set_callback(function(cvar_obj, previous, new)
    local value = tonumber(new)
    local prev_value = tonumber(previous)

    debugging_privelege_level = 0

    if value > 1 then
        cvar_obj:int(prev_value)
        debugging_privelege_level = math.clamp(value-1, 0, 2)
    end
end)

-- Other
local CHEAT = {
    NEVERLOSE = 'NL',
    GAMESENSE = 'GS',
    PRIMORDIAL = 'PRMD',
    FATALITY = 'FT',
    ONETAP = 'OT',
    PANDORA = 'PD',
    NIXWARE = 'NW',
    EVOLVE = 'EVO',
    SPIRT = 'SPRT'
}

local ICONS = {
    [CHEAT.NEVERLOSE] = 'https://raw.githubusercontent.com/tickcount/.p2c-icons/main/neverlose.png',
    [CHEAT.GAMESENSE] = 'https://raw.githubusercontent.com/tickcount/.p2c-icons/main/gamesense.png',
    [CHEAT.PRIMORDIAL] = 'https://raw.githubusercontent.com/tickcount/.p2c-icons/main/primordial.png',
    [CHEAT.FATALITY] = 'https://raw.githubusercontent.com/tickcount/.p2c-icons/main/fatality.png',
    [CHEAT.ONETAP] = 'https://raw.githubusercontent.com/tickcount/.p2c-icons/main/onetap.png',
    [CHEAT.PANDORA] = 'https://raw.githubusercontent.com/tickcount/.p2c-icons/main/pandora.png',
    [CHEAT.NIXWARE] = 'https://raw.githubusercontent.com/tickcount/.p2c-icons/main/nixware.png',
    [CHEAT.EVOLVE] = 'https://raw.githubusercontent.com/tickcount/.p2c-icons/main/ev0.png',
    [CHEAT.SPIRT] = 'https://raw.githubusercontent.com/tickcount/.p2c-icons/main/spirthack.png'
}

-- Parse Database
local base64 = require 'neverlose/base64'

local function xorstr(...)
    local str = table.concat({ ... })
    local key = '64 0e 87 3c e5 b1 4f c8 05 9a'

    local strlen, keylen = #str, #key
    local strbuf = ffi.new('char[?]', strlen+1)
    local keybuf = ffi.new('char[?]', keylen+1)

    ffi.copy(strbuf, str)
    ffi.copy(keybuf, key)

    for i=0, strlen-1 do
        strbuf[i] = bit.bxor(strbuf[i], keybuf[i % keylen])
    end

    return ffi.string(strbuf, strlen)
end

local database, database_name do
    database_name = '@vclistener'

    local decrypt_database = function(response)
        return json.parse(xorstr(base64.decode(response)))
    end

    local success, data = pcall(decrypt_database, db[database_name]) do
        database = success == true and data or { }
        db[database_name] = nil
    end
end

-- Crc32
local crc32 = (function()
    local s_crc32 = ffi.new('const uint32_t[16]', {
		0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
		0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
		0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
		0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
	})

	function mz_crc32(buff, buf_len, crc)
		crc = crc or 0

		local crcu32 = crc
		local ptr = ffi.cast('const uint8_t*', buff)

		if ptr == nil then
			return 0
		end

		crcu32 = bit.bnot(crcu32)

		while buf_len > 0 do
			local b = ptr[0]

			crcu32 = bit.bxor(bit.rshift(crcu32, 4), s_crc32[bit.bxor(bit.band(crcu32, 0xF), bit.band(b, 0xF))])
			crcu32 = bit.bxor(bit.rshift(crcu32, 4), s_crc32[bit.bxor(bit.band(crcu32, 0xF), bit.rshift(b, 4))])

			ptr = ptr + 1
			buf_len = buf_len - 1
		end

		return bit.bnot(crcu32)
	end

	local function CRC32(src, len)
		if not len then
			if type(src) == 'string' then
				len = #src
			elseif type(src) == 'cdata' then
				len = ffi.sizeof(src)
			end
		end

		if not len then
            return nil
        end

		return mz_crc32(src, len)
	end

	return CRC32
end)()

-- Common Functions
local function sort(a, b) return a.is_reliable and a.amount > b.amount end
local function get_time() return globals.realtime end

local is_using_gamesense, get_player_info do
    ffi.cdef [[
        void* VirtualAlloc(void* lpAddress, size_t dwSize, uint32_t flAllocationType, uint32_t flProtect);
        int VirtualFree(void* lpAddress, size_t dwSize, uint32_t dwFreeType);
    ]]

    local function allocate_shellcode(buffer)
        assert(type(buffer) == 'table', 'invalid shellcode')

        local sizeof = #buffer
        local base_address = ffi.C.VirtualAlloc(nil, sizeof, 0x1000, 0x40) -- MEM_COMMIT, PAGE_EXECUTE_READWRITE

        assert(base_address ~= nil, 'allocation failed')

        ffi.gc(base_address, function(memory) ffi.C.VirtualFree(memory, sizeof, 0x00008000) end)
        ffi.copy(base_address, ffi.new('char[?]', sizeof, buffer), sizeof)

        return base_address
    end

    local player_info_t = ffi.typeof [[
        struct {
            uint64_t version;
            uint32_t xuid_low;
            uint32_t xuid_high;
            char name[128];
            int userid;
            char guid[33];
            uint32_t friendsid;
            char friendsname[128];
            bool isbot;
            bool ishltv;
            uint32_t customfiles[4];
            uint8_t filesdownloaded;
        }
    ]]

    local native_GetPlayerInfo = utils.get_vfunc('engine.dll', 'VEngineClient014', 8, 'bool(__thiscall*)(void*, int, $*)', player_info_t)

    get_player_info = function(entindex)
        if type(entindex) ~= 'number' then
            return
        end

        local out = player_info_t()
        out.version = 0xFFFFFFFFFFFFF002ULL

        if native_GetPlayerInfo(entindex, out) then
            return out
        end
    end

    is_using_gamesense = ffi.cast('bool(__fastcall*)(void*, uint32_t)', allocate_shellcode {
        0x81, 0xEC, 0x4C, 0x01, 0x00, 0x00, 0x53, 0x55, 0x56, 0x8B, 0xF1, 0x89, 0x54, 0x24, 0x54, 0x33,
        0xDB, 0xC7, 0x44, 0x24, 0x10, 0x68, 0x33, 0x05, 0x97, 0x57, 0xC7, 0x44, 0x24, 0x18, 0x36, 0x06,
        0xD4, 0xEA, 0xBF, 0x00, 0x01, 0x00, 0x00, 0x8B, 0x46, 0x10, 0x8B, 0x4E, 0x14, 0x89, 0x44, 0x24,
        0x30, 0x8B, 0x46, 0x28, 0x89, 0x44, 0x24, 0x38, 0x8B, 0x46, 0x24, 0x89, 0x44, 0x24, 0x3C, 0x8B,
        0x46, 0x2C, 0x89, 0x44, 0x24, 0x40, 0x8B, 0xC3, 0xC7, 0x44, 0x24, 0x1C, 0x4F, 0xC4, 0xA4, 0x3E,
        0xC7, 0x44, 0x24, 0x20, 0x85, 0xB2, 0xAC, 0x0F, 0x89, 0x4C, 0x24, 0x34, 0x89, 0x5C, 0x24, 0x28,
        0x88, 0x44, 0x04, 0x5C, 0x40, 0x3B, 0xC7, 0x72, 0xF7, 0x8A, 0xF3, 0x8B, 0xF3, 0x8A, 0x54, 0x34,
        0x5C, 0x8B, 0xC6, 0x83, 0xE0, 0x0F, 0x8A, 0x44, 0x04, 0x14, 0x02, 0xC2, 0x02, 0xF0, 0x0F, 0xB6,
        0xCE, 0x8A, 0x44, 0x0C, 0x5C, 0x88, 0x44, 0x34, 0x5C, 0x46, 0x88, 0x54, 0x0C, 0x5C, 0x3B, 0xF7,
        0x72, 0xDB, 0x8A, 0xE3, 0x8B, 0xFB, 0xBD, 0x80, 0x00, 0x00, 0x00, 0x8A, 0xF4, 0xFE, 0xC6, 0x0F,
        0xB6, 0xF6, 0x8A, 0x54, 0x34, 0x5C, 0x02, 0xE2, 0x0F, 0xB6, 0xCC, 0x8A, 0x44, 0x0C, 0x5C, 0x88,
        0x44, 0x34, 0x5C, 0x88, 0x54, 0x0C, 0x5C, 0x83, 0xED, 0x01, 0x75, 0xE1, 0xFE, 0xC6, 0x0F, 0xB6,
        0xF6, 0x8A, 0x54, 0x34, 0x5C, 0x8A, 0xDA, 0x02, 0xDC, 0x0F, 0xB6, 0xCB, 0x8A, 0x44, 0x0C, 0x5C,
        0x88, 0x44, 0x34, 0x5C, 0x88, 0x54, 0x0C, 0x5C, 0x8A, 0x44, 0x34, 0x5C, 0x02, 0xC2, 0x0F, 0xB6,
        0xC0, 0x8A, 0x44, 0x04, 0x5C, 0x8A, 0xE3, 0x30, 0x44, 0x3C, 0x30, 0x47, 0x83, 0xFF, 0x14, 0x72,
        0xCB, 0x33, 0xFF, 0x89, 0x7C, 0x24, 0x2C, 0x8B, 0xEF, 0xC7, 0x44, 0x24, 0x24, 0x0F, 0x00, 0x00,
        0x00, 0x8B, 0x7C, 0x24, 0x24, 0xD1, 0xED, 0x89, 0x6C, 0x24, 0x48, 0x0F, 0xB7, 0x4C, 0xAC, 0x32,
        0x8B, 0xC1, 0x0F, 0xBF, 0xC9, 0x89, 0x44, 0x24, 0x54, 0x0F, 0xB7, 0x44, 0xAC, 0x34, 0xBD, 0x85,
        0x8E, 0xD5, 0x91, 0x8B, 0xD0, 0x89, 0x4C, 0x24, 0x44, 0x8B, 0xD8, 0x89, 0x54, 0x24, 0x4C, 0x8B,
        0xC1, 0x0F, 0xB7, 0xF0, 0x2B, 0xDD, 0x24, 0x0F, 0x8B, 0xD5, 0x8A, 0xC8, 0xD1, 0xC2, 0x66, 0xD3,
        0xCB, 0x8B, 0xEA, 0x66, 0x8B, 0xC3, 0xD1, 0xC5, 0x66, 0x33, 0xC6, 0x2B, 0xF2, 0x0F, 0xB7, 0xD8,
        0x8A, 0xCB, 0x80, 0xE1, 0x0F, 0x66, 0xD3, 0xCE, 0x66, 0x33, 0xF0, 0x0F, 0xB7, 0xCE, 0x0F, 0xB7,
        0xC6, 0x83, 0xEF, 0x01, 0x75, 0xCB, 0x8B, 0x7C, 0x24, 0x28, 0x8B, 0xC5, 0x2B, 0xD8, 0x89, 0x6C,
        0x24, 0x24, 0x33, 0x5C, 0x24, 0x50, 0x83, 0xC7, 0x02, 0x8B, 0x6C, 0x24, 0x48, 0xD1, 0xC0, 0x2B,
        0xC8, 0x89, 0x7C, 0x24, 0x28, 0x8B, 0x44, 0x24, 0x4C, 0x33, 0x4C, 0x24, 0x2C, 0x0F, 0xB7, 0xC0,
        0x89, 0x44, 0x24, 0x50, 0x8B, 0x44, 0x24, 0x54, 0x0F, 0xB7, 0xC0, 0x66, 0x89, 0x5C, 0xAC, 0x34,
        0x66, 0x89, 0x4C, 0xAC, 0x32, 0x89, 0x44, 0x24, 0x2C, 0x83, 0xFF, 0x09, 0x0F, 0x82, 0x45, 0xFF,
        0xFF, 0xFF, 0x8B, 0x44, 0x24, 0x30, 0x8B, 0x4C, 0x24, 0x58, 0xC1, 0xF8, 0x10, 0xC1, 0xF9, 0x10,
        0x33, 0xC1, 0xB9, 0x24, 0x24, 0x00, 0x00, 0x5F, 0x5E, 0x66, 0x3B, 0xC1, 0x5D, 0x0F, 0x94, 0xC0,
        0x5B, 0x81, 0xC4, 0x4C, 0x01, 0x00, 0x00, 0xC3
    })
end

local function is_voice_packet_reliable(ctx)
	local _msg = ffi.cast('uintptr_t*', ctx[0])

	if bit.band(bit.rshift(_msg[13], 4), 1) == 1 and ffi.cast('uintptr_t*', _msg[6] + 16)[0] ~= 0 then
		return false
	end

	if bit.band(bit.rshift(_msg[13], 6), 1) == 0 then
		return false
	end

	if _msg[8] ~= 0 then
		return false
	end

	if bit.band(_msg[13], 0x185) ~= 0x185 then
		return false
	end

	return true
end

local function get_signature(ctx)
    if type(ctx) ~= 'userdata' or ctx.entity == nil then
        return nil
    end

    if ctx.entity == entity.get_local_player() then
        return nil
    end

    local packet_reliable = is_voice_packet_reliable(ctx)
    local pct = ffi.cast('uint16_t*', ffi.cast('uint32_t', ctx[0]) + 16)[0]

    local player_info = get_player_info(ctx.entity:get_index())

    if player_info == nil or (ctx.sequence_bytes == 0 and ctx.section_number == 0 and ctx.uncompressed_sample_offset == 0) then
        return
    end

    local voice_hash = bit.lshift(
        ctx.sequence_bytes +
        ctx.section_number +
        ctx.uncompressed_sample_offset, 4
    ) % 0x100000000

    if packet_reliable == true then
        if ctx.is_nl then
            return CHEAT.NEVERLOSE, voice_hash
        end

        if is_using_gamesense(ctx[0], player_info.xuid_low) then
            return CHEAT.GAMESENSE, voice_hash
        end

        do
            local buffer = ctx.buffer

            -- parse buffer and preserve variables
            local packet = buffer:read_bits(16)
            local player_idx = buffer:read_bits(7) + 1
            local position = vector(buffer:read_coord(), buffer:read_coord(), buffer:read_coord())
            local tickcount = buffer:read_bits(32)
            local health = buffer:read_bits(7)
            local idk = buffer:read_bits(32)

            -- reset buffer
            buffer:reset()

            -- VERIFY PACKET
            local sent_entity = entity.get(player_idx)
            local time_difference = globals.server_tick - tickcount

            if sent_entity and sent_entity:is_alive() and health >= 0 and health <= 127 then
                if time_difference > 0 and time_difference * globals.tickinterval < 1 then
                    if math.abs((globals.curtime * .5) - pct) <= 2 then
                        if packet == 0xBEEF then
                            return CHEAT.NIXWARE, voice_hash
                        end

                        if packet == 0xD0D0 then
                            return CHEAT.SPIRT, voice_hash
                        end
                    end

                    return nil
                end
            end
        end

        if pct == 0x7FFA then return CHEAT.FATALITY, voice_hash end
        if pct == 0x57FA then return CHEAT.ONETAP, voice_hash end
        if pct == 0x7FFC or pct == 0x7FFD then return CHEAT.EVOLVE, voice_hash end
        if pct == 0x695B or pct == 0xAFF1 or pct == 0x1B39 then return CHEAT.PANDORA, voice_hash end

        goto packet_end
    end

    do
        -- PRIMORDIAL
        local sequence_bytes = ctx.sequence_bytes
        local uncompressed_sample_offset = ctx.uncompressed_sample_offset

        local thing = bit.bxor(
            bit.band(sequence_bytes, 0xFF),
            bit.band(bit.rshift(uncompressed_sample_offset, 16), 0xFF)
        ) - bit.rshift(sequence_bytes, 16)

        if packet_reliable == false and bit.band(thing, 0xFF) == 0x4d then
            local ent_index = bit.band(bit.bxor(
                bit.rshift(sequence_bytes, 16),
                bit.rshift(sequence_bytes, 8)
            ), 0xFF)

            local shared_entity =
                ent_index >= 1 and ent_index <= 64 and
                entity.get(ent_index)

            if shared_entity and shared_entity == ctx.entity then
                -- Only account for packets where primordial sends itself (entity == sent_entity)
                return CHEAT.PRIMORDIAL, voice_hash
            end
        end
    end

    ::packet_end::

    if backup_indexes == nil or debugging_privelege_level == 0 then
        backup_indexes = { }
    end

    if debugging_privelege_level > 0 then
        local should_print = false
        local reliability_color = packet_reliable and '\aC0FF91' or '\aFF3E3E'

        if debugging_privelege_level == 1 and pct ~= backup_indexes[ctx.entity:get_index()] then
            backup_indexes[ctx.entity:get_index()] = pct
            should_print = true
        end

        if should_print or debugging_privelege_level == 2 then
            print_raw(string.format(
                '\a9BF0EB[revealer] \aBABFCCentity: [%s] | pct: %s%d [0x%X] \aBABFCC[seqb: \aE4AF36%d\aBABFCC | secn: \aE4AF36%d\aBABFCC | ucso: \aE4AF36%d\aBABFCC]',
                ctx.entity:get_name(), reliability_color, pct, pct,
                ctx.sequence_bytes, ctx.section_number, ctx.uncompressed_sample_offset
            ))
        end
    end

    return nil
end

local function update_reliability(db)
    local sgn = { }

    for i, record in ipairs(db.records) do
        local did_find = false

        for n, val in pairs(sgn) do
            if val.signature == record.signature then
                val.amount = val.amount + 1
                val.time = math.max(val.time, record.time)

                if not val.is_reliable then
                    val.is_reliable =
                        val.amount > 4 or record.is_shared
                end

                did_find = true
                break
            end
        end

        if not did_find then
            sgn[#sgn+1] = {
                amount = 1,
                is_reliable = false,
                time = record.time,
                signature = record.signature,
            }
        end
    end

    table.sort(sgn, sort)

    db.sorted_records = sgn
end

local function verify_players(ignore_verification)
    local real_time = get_time()

    if ignore_verification ~= true then
        if math.abs(last_verification - real_time) <= 1 then
            return
        end

        last_verification = real_time
    end

    local players = { }
    local should_refresh = false

    entity.get_players(false, true, function(player)
        players[tostring(player:get_xuid())] = player
    end)

    for xuid, player in pairs(database) do
        if players[xuid] == nil or player.heartbeat > real_time or real_time-player.heartbeat >= lifetime or #player.records <= 0 then
            database[xuid] = nil
            should_refresh = true
        else
            local new_record_tbl = { }

            for id, value in ipairs(player.records) do
                if value ~= nil and value.time > real_time or real_time-value.time <= lifetime then
                    new_record_tbl[#new_record_tbl+1] = value
                end
            end

            if #new_record_tbl <= 0 then
                database[xuid] = nil
                should_refresh = true
            else
                player.records = new_record_tbl
                update_reliability(player)
            end
        end
    end

    if should_refresh == true then
        local new_database = { }

        for id, value in pairs(database) do
            if value ~= nil then
                new_database[id] = value
            end
        end

        database = new_database
    end

    return database
end

local function add_record(player, software, via_shared, custom_time, voice_hash)
    if player == nil or software == nil then
        return
    end

    -- CHEATCHECk
    local did_find = false

    for name, val in pairs(CHEAT) do
        if software == val then
            did_find = true
            break
        end
    end

    if not did_find then
        return
    end

    local real_time = custom_time or get_time()
    local xuid = tostring(player:get_xuid())

    via_shared = via_shared or false

    database[xuid] = database[xuid] or {
        heartbeat = 0,

        records = { },
        sorted_records = { },
    }

    do
        local this = database[xuid]
        local records = this.records

        this.heartbeat = real_time

        if records and #records > 0 then
            local did_scan = false

            for rid, rval in ipairs(records) do
                if did_scan then
                    break
                end

                if rval.signature == software then
                    did_scan = true

                    if math.abs(real_time-rval.time) <= .5 then
                        return
                    end
                end
            end
        end

        if #records >= 16 then
            for i=16, #records do
                table.remove(records, i)
            end
        end

        for i, val in ipairs(records) do
            if voice_hash ~= nil and voice_hash == val.hash then
                -- the exact same voice hash cannot be acknowledged twice
                return false
            end

            if software == val.signature and val.time > real_time then
                return false
            end
        end

        table.insert(records, 1, {
            signature = software,
            is_shared = via_shared,
            time = real_time,
            hash = voice_hash
        })

        update_reliability(this)

        return true
    end
end

-- Functions
local function get_all(player, reliable_only)
    if player == nil then
        return
    end

    local xuid = tostring(player:get_xuid())
    local this = database[xuid]

    if this == nil or #this.sorted_records <= 0 then
        return
    end

    local sgn = { }
    local rec_amt = #this.records

    for i, val in ipairs(this.sorted_records) do
        if reliable_only and not val.is_reliable then
            goto skip
        end

        do
            sgn[#sgn+1] = {
                signature = val.signature,
                is_reliable = val.is_reliable,
                amount = val.amount / rec_amt,
                heartbeat = get_time() - val.time
            }
        end

        ::skip::
    end

    return #sgn > 0 and sgn or nil
end

local function get_software(player)
    if player == nil then
        return
    end

    local xuid = tostring(player:get_xuid())
    local this = database[xuid]

    if this == nil or #this.sorted_records <= 0 then
        return
    end

    local best = this.sorted_records[1]

    if not best.is_reliable then
        return
    end

    return {
        signature = best.signature,
        amount = best.amount / #this.records,
        heartbeat = get_time() - best.time
    }
end

local function get_icon(signature)
    return ICONS[signature] or nil
end

local function is_in_sync()
    return is_syncing
end

do  -- Initialization
    verify_players(true)

    local function handle_voice(ctx)
        local player = ctx.entity

        if player == nil then
            return
        end

        local software, voice_hash = get_signature(ctx)

        if software == nil then
            return
        end

        add_record(player, software, false, nil, voice_hash)
    end

    local function encrypt_database()
        local unec, count = verify_players(true), 0

        for id in pairs(unec) do
            count = count + 1
        end

        db[database_name] = count > 0 and
            base64.encode(xorstr(json.stringify(unec))) or nil
    end

    local function handle_availability()
        local time = globals.realtime

        if math.abs(time - last_availability_chk) <= .1 then
            return
        end

        voice_modenable:int(1, true)
        cl_mute_enemy_team:int(0, true)
        cl_mute_all_but_friends_and_party:int(0, true)
        cl_mute_player_after_reporting_abuse:int(0, true)

        last_availability_chk = time
    end

    local function availability_fix()
        voice_modenable:int(tonumber(voice_modenable:string()))
        cl_mute_enemy_team:int(tonumber(cl_mute_enemy_team:string()))
        cl_mute_all_but_friends_and_party:int(tonumber(cl_mute_all_but_friends_and_party:string()))
        cl_mute_player_after_reporting_abuse:int(tonumber(cl_mute_player_after_reporting_abuse:string()))
    end

    -- base callbacks
    events.render(verify_players)
    events.shutdown(encrypt_database)

    -- fix game restrictions
    events.render(handle_availability)
    events.shutdown(availability_fix)

    -- voice handler
    voice_callback(handle_voice)

    local receiver do
        local RCV = {
            ID = 0xB16B00B5,
            SECURITY_KEY = '$ZGFydGh2dnY.',
            RV_PLAYER_REQUEST = 0x1,
            RV_PLAYER_SEND = 0x2
        }

        local to_int = function(str)
            local is_num = type(str) == 'number'
            local union = ffi.typeof(is_num and
                'union { uint32_t num; char bytes[5]; }' or
                'union { char bytes[5]; uint32_t num; }'
            )(str)

            return is_num and ffi.string(union.bytes) or union.num
        end

        local resolve_hash = function(number, rcv)
            local hash = bit.bxor(number, rcv)

            hash = hash
                + bit.lshift(hash, 1)
                + bit.lshift(hash, 4)
                + bit.lshift(hash, 7)
                + bit.lshift(hash, 8)
                + bit.lshift(hash, 24)

            return hash % 0x100000000
        end

        local function send_player(player, signature, time_difference)
            voice_callback:call(function(message)
                local server_tick = globals.server_tick
                local tick_hash = resolve_hash(server_tick, RCV.ID)

                message:write_bits(server_tick, 32)
                message:write_bits(tick_hash, 32)
                message:write_bits(RCV.ID, 32)
                message:write_bits(RCV.RV_PLAYER_SEND, 4)
                message:write_bits(player:get_index() - 1, 7)
                message:write_bits(to_int(signature), 32)
                message:write_bits(time_difference, 16)

                message:crypt(RCV.SECURITY_KEY)

                -- print('RV_PLAYER_SEND '', player:get_name(), '' -> ', signature)
            end)
        end

        local function request_players()
            voice_callback:call(function(message)
                local server_tick = globals.server_tick
                local tick_hash = resolve_hash(server_tick, RCV.ID)

                message:write_bits(server_tick, 32)
                message:write_bits(tick_hash, 32)
                message:write_bits(RCV.ID, 32)
                message:write_bits(RCV.RV_PLAYER_REQUEST, 4)

                message:crypt(RCV.SECURITY_KEY)
            end)
        end

        local function RECEIVER(ctx)
            if type(ctx) ~= 'userdata' or ctx.entity == nil then
                return
            end

            local buffer = ctx.buffer

            buffer:crypt(RCV.SECURITY_KEY)

            local tick = buffer:read_bits(32)
            local hash_sum = buffer:read_bits(32)
            local packet = buffer:read_bits(32)

            if packet ~= RCV.ID then
                return
            end

            local action = buffer:read_bits(4)

            if action == RCV.RV_PLAYER_REQUEST then
                if to_time(globals.server_tick - tick) < 1 and hash_sum == resolve_hash(tick, RCV.ID) then
                    is_syncing = true

                    local next_request = 0

                    -- print_raw('\aFF0000RV_PLAYER_REQUEST from: ', entity.get(ctx.entity):get_name())

                    entity.get_players(false, true, function(player)
                        local software = get_software(player)

                        if software ~= nil then
                            utils.execute_after(next_request, send_player, player, software.signature, to_ticks(software.heartbeat))
                            next_request = next_request + to_time(5)
                        end
                    end)

                    utils.execute_after(next_request, function()
                        is_syncing = false
                    end)
                end

                return
            end

            if action == RCV.RV_PLAYER_SEND then
                local tick = buffer:read_bits(32)
                local hash_sum = buffer:read_bits(32)

                if to_time(globals.server_tick - tick) < 1 and hash_sum == resolve_hash(tick, RCV.ID) then
                    local player = entity.get(buffer:read_bits(7) + 1)
                    local signature = to_int(buffer:read_bits(32))
                    local heartbeat = to_time(buffer:read_bits(16))

                    local found_sig

                    for id, value in pairs(CHEAT) do
                        if signature == value then
                            found_sig = id
                            break
                        end
                    end

                    if player ~= nil and found_sig and heartbeat < 120 then
                        local response = add_record(player, signature, true, get_time() - heartbeat)

                        -- print(string.format(
                        --     'RV_PLAYER_ACKNOWLEDGE [%s] [%s:%.2f]%s',
                        --     player:get_name(), signature, heartbeat, response == false and ' [REJECTED]' or ''
                        -- ))
                    end
                end
            end
        end

        voice_callback(RECEIVER)

        -- REGISTER
        if globals.is_in_game then
            local count = 0

            for _ in pairs(database) do
                count = count + 1
            end

            if count == 0 then
                request_players()
            end
        end

        events.player_connect_full(function(e)
            if entity.get(e.userid, true) == entity.get_local_player() then
                request_players()
            end
        end)
    end
end

return {
    get_all = get_all,
    get_software = get_software,
    get_icon = get_icon,
    is_syncing = is_in_sync
}
