-- (c) 2023 Propagram. MIT Licensed.

local ffi = require("ffi")

-- luarocks install lockbox
local Bit = require("lockbox.util.bit")
local Array = require("lockbox.util.array")
local PBKDF2 = require("lockbox.kdf.pbkdf2")
local HMAC = require("lockbox.mac.hmac")
local SHA2_256 = require("lockbox.digest.sha2_256")

local MAX_VALUE = 0x7fffffff

local bor, band, lshift, rshift, bxor, arshift = Bit.bor, Bit.band, Bit.lshift, Bit.rshift, Bit.bxor, Bit.arshift

local function checkAndInit(key, salt, N, r, p)
    if N == 0 or band(N, (N - 1)) ~= 0 then
        error('N must be > 0 and a power of 2')
    end
    if N > MAX_VALUE / 128 / r then
        error('Parameter N is too large')
    end
    if r > MAX_VALUE / 128 / p then
        error('Parameter r is too large')
    end

    local XY = ffi.new("int[?]", 256 * r)
    
    local V = ffi.new("int[?]", 128 * r * N)

    local B32 = ffi.new("int[?]", 16)

    local x = ffi.new("int[?]", 16)

    local _X = ffi.new("int[?]", 64)

    local oB = PBKDF2()
      .setPRF(HMAC().setBlockSize(64).setDigest(SHA2_256))
      .setDKeyLen(p * 128 * r)
      .setIterations(1)
      .setSalt(Array.fromString(salt))
      .setPassword(Array.fromString(key))
      .finish()
      .asBytes()
    
    local B = ffi.new("int[?]", #oB)
    for i = 1, #oB do
      B[i-1] = oB[i]
    end

    return XY, V, B32, x, _X, B
end


local function copy(source, target, targetStart, sourceStart, sourceEnd)
  local j = (targetStart or 0)
  for i = (sourceStart or 0), sourceEnd or (ffi.sizeof(source) / ffi.sizeof("int")) do
    target[j] = source[i]
    j = j + 1
  end
end

local function arraycopy(src, srcPos, dest, destPos, length)
  return copy(src, dest, destPos, srcPos, srcPos + length)
end

local function R(a, b)
  return bor(lshift(a, b), rshift(a, 32 - b))
end

local function salsa20_8(B, B32, x)

  for i = 0, 15 do
    B32[i] = lshift(band(B[i * 4 + 0], 0xff), 0)
    B32[i] = bor(B32[i], lshift(band(B[i * 4 + 1], 0xff), 8))
    B32[i] = bor(B32[i], lshift(band(B[i * 4 + 2], 0xff), 16))
    B32[i] = bor(B32[i], lshift(band(B[i * 4 + 3], 0xff), 24))
  end

  arraycopy(B32, 0, x, 0, 16)

  for _ = 8, 1, -2 do
    x[4] = bxor(x[4], R(x[0] + x[12], 7))
    x[8] = bxor(x[8], R(x[4] + x[0], 9))
    x[12] = bxor(x[12], R(x[8] + x[4], 13))
    x[0] = bxor(x[0], R(x[12] + x[8], 18))
    x[9] = bxor(x[9], R(x[5] + x[1], 7))
    x[13] = bxor(x[13], R(x[9] + x[5], 9))
    x[1] = bxor(x[1], R(x[13] + x[9], 13))
    x[5] = bxor(x[5], R(x[1] + x[13], 18))
    x[14] = bxor(x[14], R(x[10] + x[6], 7))
    x[2] = bxor(x[2], R(x[14] + x[10], 9))
    x[6] = bxor(x[6], R(x[2] + x[14], 13))
    x[10] = bxor(x[10], R(x[6] + x[2], 18))
    x[3] = bxor(x[3], R(x[15] + x[11], 7))
    x[7] = bxor(x[7], R(x[3] + x[15], 9))
    x[11] = bxor(x[11], R(x[7] + x[3], 13))
    x[15] = bxor(x[15], R(x[11] + x[7], 18))
    x[1] = bxor(x[1], R(x[0] + x[3], 7))
    x[2] = bxor(x[2], R(x[1] + x[0], 9))
    x[3] = bxor(x[3], R(x[2] + x[1], 13))
    x[0] = bxor(x[0], R(x[3] + x[2], 18))
    x[6] = bxor(x[6], R(x[5] + x[4], 7))
    x[7] = bxor(x[7], R(x[6] + x[5], 9))
    x[4] = bxor(x[4], R(x[7] + x[6], 13))
    x[5] = bxor(x[5], R(x[4] + x[7], 18))
    x[11] = bxor(x[11], R(x[10] + x[9], 7))
    x[8] = bxor(x[8], R(x[11] + x[10], 9))
    x[9] = bxor(x[9], R(x[8] + x[11], 13))
    x[10] = bxor(x[10], R(x[9] + x[8], 18))
    x[12] = bxor(x[12], R(x[15] + x[14], 7))
    x[13] = bxor(x[13], R(x[12] + x[15], 9))
    x[14] = bxor(x[14], R(x[13] + x[12], 13))
    x[15] = bxor(x[15], R(x[14] + x[13], 18))
  end

  for i = 0, 15 do
    B32[i] = (((x[i] + B32[i]) + 2^31) % (2^32)) - (2^31) -- https://stackoverflow.com/questions/37411564/hex-to-int32-value
  end
 
  for i = 0, 15 do
      local bi = i * 4
      B[bi + 0] = band(arshift(B32[i ], 0), 0xff)
      B[bi + 1] = band(arshift(B32[i], 8), 0xff)
      B[bi + 2] = band(arshift(B32[i], 16), 0xff)
      B[bi + 3] = band(arshift(B32[i], 24), 0xff)
  end

end

local function blockxor(S, Si, D, Di, len)
  for i = 0, len - 1 do
    D[Di + i] = bxor(D[Di + i], S[Si + i])
  end
end

local function blockmix_salsa8(BY, Bi, Yi, r, _X, B32, x)
  arraycopy(BY, Bi + (2 * r - 1) * 64, _X, 0, 64)

  for i = 0, (2 * r) - 1 do
    blockxor(BY, i * 64, _X, 0, 64)
    salsa20_8(_X, B32, x)
    arraycopy(_X, 0, BY, Yi + (i * 64), 64)
  end
  for i = 0, r - 1  do
    arraycopy(BY, Yi + (i * 2) * 64, BY, Bi + (i * 64), 64)
  end
  for i = 0, r - 1 do
    arraycopy(BY, Yi + (i * 2 + 1) * 64, BY, Bi + (i + r) * 64, 64)
  end
end

local function checkOffset(offset, ext, length)
  if offset % 1 ~= 0 or offset < 0 then
    error('offset is not uint', 0)
  end
  if offset + ext > length then
    error('Trying to access beyond buffer length', 0)
  end
end

local function readUInt32LE(buffer, offset, noAssert)
  offset = rshift(offset, 0)
  if not noAssert then
    checkOffset(offset, 4, ffi.sizeof(buffer) / ffi.sizeof("int"))
  end
  return bor(
    buffer[offset],
    lshift(buffer[offset + 1], 8),
    lshift(buffer[offset + 2], 16)
  ) + buffer[offset + 3] * 0x1000000
end

local function smix(B, Bi, r, N, V, XY, _X, B32, x)
    local Xi = 0
    local Yi = 128 * r
    copy(B, XY, Xi, Bi, Bi + Yi)
    for i = 0, N - 1 do
      copy(XY, V, i * Yi, Xi, Xi + Yi)
      blockmix_salsa8(XY, Xi, Yi, r, _X, B32, x)
    end

    for _ = 0, N - 1 do
        local offset = Xi + (2 * r - 1) * 64
        local j = band(readUInt32LE(XY, offset), N - 1)
        blockxor(V, j * Yi, XY, Xi, Yi)
        blockmix_salsa8(XY, Xi, Yi, r, _X, B32, x)
    end
    copy(XY, B, Bi, Xi, Xi + Yi)
end

return function (key, salt, N, r, p, dkLen)
  local XY, V, B32, x, _X, B = checkAndInit(key, salt, N, r, p)
  for i = 0, p - 1 do
    smix(B, i * 128 * r, r, N, V, XY, _X, B32, x)
  end
  
  local oB = {}
  for i = 1, ffi.sizeof(B) / ffi.sizeof("int") do
    oB[i] = B[i - 1]
  end

  return PBKDF2()
    .setPRF(HMAC().setBlockSize(64).setDigest(SHA2_256))
    .setDKeyLen(dkLen)
    .setIterations(1)
    .setSalt(oB)
    .setPassword(Array.fromString(key))
    .finish()
    .asHex()
end
