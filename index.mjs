import { createCipheriv, randomBytes, scryptSync } from "crypto";
import { createReadStream, createWriteStream } from "fs";
import { basename, join } from "path";
import { createInterface } from "readline";

const { log } = console;

const encrypt = (text, password) => {
  const algorithm = "aes-256-cbc";
  const key = scryptSync(password, `salt`, 32);
  const ivBuff = randomBytes(16);
  const cipher = createCipheriv(algorithm, key, ivBuff);
  const encrypted = cipher.update(text, `utf8`, `hex`) + cipher.final(`hex`);
  const iv = ivBuff.toString(`hex`);
  const encryptedIv = Buffer.from(JSON.stringify({ encrypted, iv }), `utf8`).toString(`base64`);
  return encryptedIv;
};

const [inputFilePath, password] = process.argv.slice(2);

if (!inputFilePath || !password) {
  console.error("Usage: node encrypt.mjs INPUT_FILE PASSWORD");
  process.exit(1);
}

const inputFileName = basename(inputFilePath);
const outputFilePath = join(process.cwd(), `${inputFileName}.encrypted.txt`);
const inputStream = createReadStream(inputFilePath, { encoding: "utf8" });
const outputStream = createWriteStream(outputFilePath, { encoding: "utf8" });
const inputLines = createInterface({ input: inputStream });

const processBlock = block => {
    const encryptedLine = encrypt(block[3], password);
    const newBlock = `${block[0]}\r\n${block[1]}\r\n${block[2]}\r\n${encryptedLine}\r\n\r\n`;
    outputStream.write(newBlock);
    log(newBlock);
}


let block = [];

for await (const line of inputLines) {
  block.push(line);

  if (block.length === 5) {
    processBlock(block);
    block = [];
  }
}

if (block.length === 4) {
    processBlock(block);
    process.exit(0);
}

if (block.length > 0) {
  log("Incomplete block at end of file");
  process.exit(1);
}
