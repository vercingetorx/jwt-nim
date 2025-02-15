import std/[base64, json, strutils, strformat]

import jwt_nim/[hmac, secrets]


# NOTE: https://www.rfc-editor.org/rfc/rfc7519.txt


proc base64Encode[T](data: openarray[T]): string {.inline.} =
  ## convenience proc
  return data.encode(safe=true).strip(leading=false, chars={'='})


proc base64Decode(data: string): string {.inline.} =
  ## convenience proc
  return fmt"{data}==".decode()


proc splitToken(token: string): tuple[header, payload, signature: string] {.inline.} =
  ## convenience proc
  if token.count('.') == 2:
    let parts = token.split('.')
    result.header = parts[0]
    result.payload = parts[1]
    result.signature = parts[2]


proc sign*(payload, secret: string, digestMod: DigestMod = SHA256): string =
  ## currently implemented hash types SHA256, SHA512
  var alg: string
  if digestMod == SHA256:
    alg = "HS256"
  else:
    alg = "HS512"

  let header = %* {
    "alg": alg,
    "typ": "JWT"
  }

  let encodedHeader = base64Encode($header)
  let encodedPayload = base64Encode(payload)

  var signature = newHmacCtx(
    key=secret,
    msg=fmt"{encodedHeader}.{encodedPayload}",
    digestMod=digestMod
  )

  return fmt"{encodedHeader}.{encodedPayload}.{base64Encode(signature.digest())}"


proc sign*(payload: JsonNode, secret: string, digestMod: DigestMod = SHA256): string =
  ## currently implemented hash types SHA256, SHA512
  var alg: string
  if digestMod == SHA256:
    alg = "HS256"
  else:
    alg = "HS512"

  let header = %* {
    "alg": alg,
    "typ": "JWT"
  }

  let encodedHeader = base64Encode($header)
  let encodedPayload = base64Encode($payload)

  var signature = newHmacCtx(
    key=secret,
    msg=fmt"{encodedHeader}.{encodedPayload}",
    digestMod=digestMod
  )

  return fmt"{encodedHeader}.{encodedPayload}.{base64Encode(signature.digest())}"


proc verify*(token, secret: string, digestMod: DigestMod = SHA256): bool =
  let (header, payload, signature) = token.splitToken()
  let (_, _, expectedSignature) = sign(base64Decode(payload), secret, digestMod=digestMod).splitToken()

  return signature == expectedSignature


when isMainModule:
  # NOTE: tested against https://jwt.io/

  let secret = tokenUrlSafe(128)
  # NOTE: claims
  let payload = %* {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
  }

  let token = sign(payload, secret)
  echo fmt"JWT: {token}"

  let isValid = verify(token, secret)
  echo fmt"valid token: {isValid}"
