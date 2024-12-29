/**
 * converter
 */
const
StrToUint8 = string => Uint8Array.from([...string].map(ch => ch.charCodeAt())),
Uint8ToAb = uint8array => uint8array.buffer,
StrToAb = string => Uint8ToAb(StrToUint8(string)),
AbToUint8 = arrayBuff => new Uint8Array(arrayBuff),
AbToStr = arrayBuff => Uint8ToStr(AbToUint8(arrayBuff)),
Uint8ToStr = uint8array => uint8array.reduce((data, byte) => data + String.fromCharCode(byte), ''),   
ObjToJson = object => JSON.stringify(object),
JsonToObj = string => JSON.parse(string),
StrToB64 = string => btoa(string),
B64ToStr = base64 => atob(base64),
AbToB64 =  arrayBuff => StrToB64(AbToStr(arrayBuff)),
B64ToAb =  base64 => StrToAb(B64ToStr(base64)),
ObjToB64 =  object => StrToB64(ObjToJson(object)),
B64ToObj =  base64 => JsonToObj(B64ToStr(base64)),
//synchronous convertion Blob/File <-> DataURL
BlobToDataUrl = fileOrBlob => {
    let 
    url = URL.createObjectURL(fileOrBlob),
    xhr = new XMLHttpRequest()
    xhr.open('GET', url, false)
    xhr.overrideMimeType('text/plain; charset=x-user-defined')
    xhr.send()
    URL.revokeObjectURL(url)
    return `data:${fileOrBlob.type};base64,` + btoa(xhr.responseText.split('').map(c => String.fromCharCode(c.charCodeAt(0)&0xff)).join(''))
},
//synchronous convertion DataURL <-> Blob/File
DataUrlToBlob =  dataUrl => {
    let 
    str = atob(dataUrl.split(',')[1]),
    type = dataUrl.match(/:([a-z/-]+);/)[1],
    buffer = StrToUint8(str).buffer // new Uint8Array(str.split('').map(c => c.charCodeAt(0))).buffer
    return new Blob([buffer], {type: type})
}

export { 
    StrToUint8, 
    Uint8ToAb, 
    StrToAb, 
    AbToUint8, 
    AbToStr, 
    Uint8ToStr, 
    ObjToJson, 
    JsonToObj, 
    StrToB64, 
    B64ToStr, 
    AbToB64, 
    B64ToAb, 
    ObjToB64, 
    B64ToObj, 
    BlobToDataUrl, 
    DataUrlToBlob 
}