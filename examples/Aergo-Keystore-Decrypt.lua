-- luarocks install scrypt
local Scrypt = require("scrypt")

-- luarocks install lockbox
local Digest = require("lockbox.digest.sha2_256")
local Stream = require("lockbox.util.stream")
local CTRMode = require("lockbox.cipher.mode.ctr")
local Array = require("lockbox.util.array")
local ZeroPadding = require("lockbox.padding.zero")
local AES128Cipher = require("lockbox.cipher.aes128")

-- luarocks install rxi-json-lua
local json = require("json")

return function(keystore_file, keystore_password)

  local file = io.open(keystore_file, "r")
  local content = file:read("*a")
  file:close()

  local keystore = json.decode(content)

  local encryptionKey = Scrypt(keystore_password, Array.toString(Array.fromHex(keystore.kdf.params.salt)), keystore.kdf.params.n, keystore.kdf.params.r, keystore.kdf.params.p, keystore.kdf.params.dklen)

  local mac = string.lower(Digest().update(Stream.fromHex(encryptionKey:sub(33) ..  keystore.cipher.ciphertext)).finish().asHex())

  if keystore.kdf.mac ~= mac then
    error("invalid mac")
  end

  local decipher = CTRMode.Decipher()
    .setKey(Array.fromHex(encryptionKey:sub(1, 32)))
    .setBlockCipher(AES128Cipher)
    .setPadding(ZeroPadding)

  local rawPrivateKey = decipher
    .init()
    .update(Stream.fromArray(Array.fromHex(keystore.cipher.params.iv)))
    .update(Stream.fromArray(Array.fromHex(keystore.cipher.ciphertext)))
    .finish()
    .asBytes()

  return rawPrivateKey, Array.toHex(rawPrivateKey)
end
