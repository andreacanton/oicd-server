import crypto from "node:crypto";

const KEY_FILE = "keys.json";
let keys: { publicKey: string; privateKey: string };

const keysFile = Bun.file(KEY_FILE);

if (await keysFile.exists()) {
  keys = await keysFile.json();
} else {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  keys = {
    publicKey,
    privateKey,
  };
  await Bun.write(keysFile, JSON.stringify(keys));
  console.info("Generated and saved new RSA keys.");
}

export const privateKey = keys.privateKey;
export const publicKey = keys.publicKey;
