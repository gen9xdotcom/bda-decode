const crypto_1 = require("crypto");
const fs = require('fs');

function decrypt(rawData, key) {
    let data = JSON.parse(rawData);
    let dk = Buffer.concat([Buffer.from(key), Buffer.from(data.s, "hex")]);
    let arr = [Buffer.from((0, crypto_1.createHash)("md5").update(dk).digest()).toString("hex")];
    let result = arr[0];
    for (let x = 1; x < 3; x++) {
        arr.push(Buffer.from((0, crypto_1.createHash)("md5")
            .update(Buffer.concat([Buffer.from(arr[x - 1], "hex"), dk]))
            .digest()).toString("hex"));
        result += arr[x];
    }
    let aes = (0, crypto_1.createDecipheriv)("aes-256-cbc", Buffer.from(result.substring(0, 64), "hex"), Buffer.from(data.iv, "hex"));
    return aes.update(data.ct, "base64", "utf8") + aes.final("utf8");            
}


(async () => {

    let grus = await fs.readFileSync(`./bda.txt`).toString().replaceAll("\r", "").split("\n")[0];
    let decode1 = new Buffer.from(grus, 'base64'); // Ta-da
    let userAgent = await fs.readFileSync(`./useragent.txt`).toString().replaceAll("\r", "").split("\n")[0];
    let time = new Date().getTime() / 1000; //timestamp = int(time.time())
    let key = userAgent + Math.round(time - (time % 21600));
    try {
        let decode = decrypt(decode1.toString(), key);
        console.log(`BDA's decoded`)
        await fs.writeFileSync(`./decode.txt`, decode);     
    } catch (error) {
        console.log(`Failed to decode, please check input value`)        
    }
})();
