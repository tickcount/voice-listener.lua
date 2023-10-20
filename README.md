# voice-listener.lua
A cheat revealing library for CS:GO

Available cheats: Neverlose, Gamesense, Primordial, Fatality, Onetap, Pandora, Nixware, Evolve, Spirthack

## Information
In the end of 2022 esoterik (gamesense developer) decided to go full-schizo mode and encrypt shared esp packets with his own techniques because he didn't like the fact that my cheat revealer existed. AFAIK in the recent updates he even decided virtualize some parts of the sharedesp code to make it harder to reverse-engineer.

[This part of the code (L198)](https://github.com/tickcount/voice-listener.lua/blob/ee363896627ddc64a367488edf50d823255d9ca3/voice-listener.lua#L198) basically executes the shellcode (reversed part of the shared esp decryption from gamesense) and returns true if it matches the gamesense shared esp packet. I didn't have much time to port it to lua so i just left it the way it is, feel free to reverse it.

In order to prevent others from stealing shared packets, esoterik made a hash for each player that consists of entity_index / steamid and other factors, the packet is considered valid if the hash matches the magical number `0x2424` (ASCII Symbol: `$$`)

![meme](https://i.imgur.com/REjONmo.png)

## Example
```Lua
local listener = require 'voice-listener.lua'

local players = { }

local function reset()
    local me = entity.get_local_player()

    if me == nil then
        return
    end

    entity.get_players(false, true, function(player)
        local xuid = player:get_xuid()

        if players[xuid] then
            player:set_icon()
            players[xuid] = nil
        end
    end)
end

local function on_net_update()
    local online_players = { }

    entity.get_players(false, true, function(player)
        local xuid = player:get_xuid()
        local detection = listener.get_software(player)

        online_players[xuid] = player

        if not detection and players[xuid] then
            players[xuid] = nil
            player:set_icon()
        end

        if detection then
            local icon = listener.get_icon(detection.signature)

            if icon then
                players[xuid] = detection
                player:set_icon(icon)
            end
        end
    end)

    for id in pairs(players) do
        if online_players[id] == nil then
            players[id] = nil
        end
    end
end

local function on_shutdown()
    reset()
end

events.net_update_end(on_net_update)
events.shutdown(on_shutdown)
```
