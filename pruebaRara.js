//-----------------------------------------------------------------------------
// FUNCIONES Y GLOBALES

selectApdu = "80 A4";
readRecordApdu  = "80 B2";
writeRecordApdu = "8C D2"; //Modified to enable Secure Messaging

startSessionApdu = "80 84 00 00 08";
authenticateApdu = "80 82 00 00 10";
getResponseApdu  = "80 C0 00 00 08";

//-----------------------------------------------------------------------------
card = new Card();
var crypto = new Crypto();
var deskey = new Key();

atr = card.reset(Card.RESET_COLD);

Kt = new ByteString("AA 00 AA 01 AA 02 AA 03", HEX);
Kc = new ByteString("DD 00 DD 01 DD 02 DD 03", HEX); 

//---------------------------------------- Start Session
RNDc = card.plainApdu(new ByteString(startSessionApdu, HEX));
//RNDc = new ByteString("00 00 00 00 00 00 00 00", HEX);
print ("TRACE: RNDc  " + RNDc)
//---------------------------------------- Authenticate

deskey.setComponent(Key.DES, Kt);
encryptedMsg =  crypto.encrypt(deskey, Crypto.DES_ECB, RNDc);
RNDt =  crypto.generateRandom(8);
msg = encryptedMsg.concat(RNDt);
print ("TRACE: auth message  " + msg);

card.plainApdu(new ByteString(authenticateApdu, HEX).concat(msg));
//---------------------------------------- If All OK, get response from card and calculate Ks
resp = card.plainApdu(new ByteString(getResponseApdu, HEX));
print ("TRACE: Authenticate Response  " + resp);

//---------------------------------------- Calculate and Verify Ks
deskey.setComponent(Key.DES, Kc);
enc1 = crypto.encrypt(deskey, Crypto.DES_ECB, RNDc);
toEnc = enc1.xor(RNDt);

deskey.setComponent(Key.DES, Kt);
Ks = crypto.encrypt(deskey, Crypto.DES_ECB, toEnc);
//---------------------------------------- Verify Ks

deskey.setComponent(Key.DES, Ks);
verifier = crypto.encrypt(deskey, Crypto.DES_ECB, RNDt);

assert(verifier.equals(resp));

//--------------------------------------- Secure Write
fileId = "8DC4";

msg = new ByteString("MASTER SSDDEE.2017. Ignacio Barrio", ASCII);

msgPadded = msg.pad(Crypto.ISO9797_METHOD_2, true); //padded to next multiple of 8, ONLY TWO BYTES. SO ONLY 80 IS ADDED

paddingInd = (msgPadded.length - msg.length).toString(16); // SHOULD BE 2 ->

if (paddingInd.length % 2 != 0) {
	paddingInd = "0" + paddingInd; //SHOULD BE 02
}

IV = RNDc.and(new ByteString("00 00 00 00 00 00 FF FF", HEX)); //tHIS IS A FORMULA, SO LET'S SAY IT'S OK
MacIV = RNDc.and(new ByteString("00 00 00 00 00 00 FF FF", HEX)).add(1);

encriptedData = crypto.encrypt(deskey, Crypto.DES_CBC, msgPadded, IV);

L87 = (encriptedData.length+1).toString(16); //

//-------------------------- Calculate MAC
AuthCode = new ByteString("89 04" + writeRecordApdu + "08 00" + "87" + L87 + paddingInd, HEX).concat(encriptedData);
print("Clear MAC: " + AuthCode.toString());

AuthCode = AuthCode.pad(Crypto.ISO9797_METHOD_2, true);

encryptedAuthCode = crypto.encrypt(deskey, Crypto.DES_CBC, AuthCode, MacIV);

print("Encripted Authenticated Code: " + encryptedAuthCode.toString());

MAC = encryptedAuthCode.right(8).left(4);
print("Message Authentication Code: " + MAC.toString());
//----------------------------------------

//secureWriteApdu = writeRecordApdu.concat(record, offset, msgTotalLength, "87", L87, paddingInd, encriptedData, "8E", "04", MAC) //plainApdu version
secureWrite = "87" + L87 + paddingInd + encriptedData + "8E" + "04"; //sendApdu version

print ("-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-");
print ("msg not padded:\n"+msg);
print ("msg not encripted:\n"+msgPadded);
print ("encripted data:\n"+encriptedData);
print ("mac:\n"+MAC);
print ("APDU:\n"+secureWrite);//Apdu);

card.plainApdu(new ByteString(selectApdu.concat("00 00 02", fileId), HEX));
if ( card.SW.toString(16) == "9103")
  {
    print ("Writing with Secure Messaging");
    resp = card.sendApdu(0x8C, 0xD2, 0x08, 0x00, new ByteString(secureWrite, HEX).concat(MAC));
    print("resp: " + resp);
    print("C�digo SW: " + card.SW.toString(16));
  }


//print ("in text: " + resp.toString(ASCII));
