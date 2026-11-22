import { createHmac } from "node:crypto"

// RFC 6238 codes, as an authenticator app computes them: SHA-1, 6 digits,
// 30-second steps, from the base32 secret the enrollment page shows.
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

export function currentStep(): number {
  return Math.floor(Date.now() / 30_000)
}

export function totp(secret: string, step: number): string {
  const bits = [...secret.replace(/=+$/, "").toUpperCase()]
    .map((char) => {
      const value = BASE32.indexOf(char)
      if (value < 0) throw new Error(`Not base32: ${char}`)
      return value.toString(2).padStart(5, "0")
    })
    .join("")
  const key = Buffer.from(
    (bits.match(/.{8}/g) ?? []).map((byte) => Number.parseInt(byte, 2)),
  )
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(step))
  const digest = createHmac("sha1", key).update(counter).digest()
  const offset = digest[digest.length - 1] & 0xf
  const value = (digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000
  return String(value).padStart(6, "0")
}
