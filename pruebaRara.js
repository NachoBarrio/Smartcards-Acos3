intents = "";

card = new Card();
atr = card.reset(Card.RESET_COLD);


crypto = new Crypto();
deskey = new Key();


certifyKey       = new ByteString("A0 A1 A2 A3 A4 A5 A6 A7", HEX); //Kcf
revokeDebitKey   = new ByteString("B0 B1 B2 B3 B4 B5 B6 B7", HEX); //Kcr

startSessionApdu = "80 84 00 00 08";
authenticateApdu = "80 82 00 00 10";
getResponseApdu  = "80 C0 00 00 0C";
inquireAccApdu   = "";
  
Kt = new ByteString("AA 00 AA 01 AA 02 AA 03", HEX);
Kc = new ByteString("DD 00 DD 01 DD 02 DD 03", HEX);
Ks = new ByteString('', HEX);

seqNumber = new ByteString('', HEX);
IvAccount = new ByteString("00 00 00 00 00 00 00 00", HEX);
IvSecure  = new ByteString('', HEX);

referenceData    = crypto.generateRandom(4).pad(Crypto.ISO9797_METHOD_2, true);
keyNumber        = "02";
inquireData      = new ByteString('', HEX);
inquirePadding   = "0" + (referenceData.length - 4).toString(16);

function mutualAuth(){
  //---------------------------------------- Start Session
  RNDc = card.plainApdu(new ByteString(startSessionApdu, HEX));
  IvSecure = RNDc.and(new ByteString("00 00 00 00 00 00 FF FF", HEX));
  seqNumber = IvSecure.add(1);
  
  //---------------------------------------- Authenticate
  deskey.setComponent(Key.DES, Kt);
  encryptedMsg =  crypto.encrypt(deskey, Crypto.DES_ECB, RNDc);
  RNDt =  crypto.generateRandom(8);
  msg = encryptedMsg.concat(RNDt);
  card.plainApdu(new ByteString(authenticateApdu, HEX).concat(msg));
  //---------------------------------------- Get response and calculate Ks
  resp = card.plainApdu(new ByteString(getResponseApdu, HEX));
  //---------------------------------------- Verify Ks
  deskey.setComponent(Key.DES, Kc);
  enc1 = crypto.encrypt(deskey, Crypto.DES_ECB, RNDc);
  toEnc = enc1.xor(RNDt);
  deskey.setComponent(Key.DES, Kt);
  Ks = crypto.encrypt(deskey, Crypto.DES_ECB, toEnc);
  //---------------------------------------- Verify Ks
  deskey.setComponent(Key.DES, Ks);
  verifier = crypto.encrypt(deskey, Crypto.DES_ECB, RNDt);
  assert(verifier.equals(resp));
  print("auth done");
};

function inquireSM() {
  //--------------------------------------------- INQUIRE WITH SECURE MESSAGING
  inquireData = crypto.encrypt(deskey, Crypto.DES_CBC, referenceData, IvSecure);


  P3 = (9 + inquireData.length).toString(16);
  L87 = "0" + (inquireData.length+1).toString(16);
  
  inquireAccApdu   = "8C E4 " + keyNumber +" 00";
  secureData = new ByteString("87" + L87 + inquirePadding, HEX).concat(inquireData);

  commandHeaderTLV =  new ByteString("89 04" + inquireAccApdu, HEX);
  AuthCode = commandHeaderTLV.concat(secureData).pad(Crypto.ISO9797_METHOD_2, true);
  encryptedAuthCode = crypto.encrypt(deskey, Crypto.DES_CBC, AuthCode, seqNumber);

  MAC = encryptedAuthCode.right(8).left(4);
  print("inquire done");
}

function getInquireResponse() {
  card.plainApdu(new ByteString(inquireAccApdu.concat(P3), HEX).concat(secureData).concat(new ByteString("8E 04", HEX)).concat(MAC));
  getResponseApdu  = "80 C0 00 00 17";
  
  response = card.plainApdu(new ByteString(getResponseApdu, HEX));
//----------------------------------------------- Verify SM MAC  
  if (response != "") {
    print ("TRACE --- Inquire - Checking Secure Inquire Response");
    print ("Reveived Response: " + response)
    swStatus = response.right(8).left(2);
    print ("Card Status after Inquire Account  :" +swStatus);
    receivedMac = response.right(4);
    macVerifier = commandHeaderTLV.concat(response.left(response.length - 6)).pad(Crypto.ISO9797_METHOD_2, true);

    print ("MAC verifier:   " + macVerifier);

    encryptedMacVerifier = crypto.encrypt(deskey, Crypto.DES_CBC, macVerifier, seqNumber).right(8).left(4);

    print ("Received MAC:   " + receivedMac);
    print ("Verifier MAC:   " + encryptedMacVerifier);
    
    assert(receivedMac.equals(encryptedMacVerifier));
    print ("Received MAC Encripted with Ks - ok");

//----------------------------------------------------- Verify Inquire Account MAC with Kcf
    encriptedDataLength  = response.bytes(1,1).toSigned() - 1;
    encriptedDataPadding = response.bytes(2,1).toSigned();
    encripted = response.bytes(3, encriptedDataLength);
    decriptedData = crypto.decrypt(deskey, Crypto.DES_CBC, encripted, seqNumber);
    
    print ("dataCript:  " + encripted)
    print ("datalength: " + encriptedDataLength)
    print ("dataPadd:   " + encriptedDataPadding)
    print ("dataPadded: " + decriptedData)
    
    data = decriptedData.left(encriptedDataLength - encriptedDataPadding)   
    inquireAccMAC = data.left(4);
    data = data.bytes(4)
    
    transactionType = data.bytes(0,1);
    balance = data.bytes(1,3);
    ATREF = data.bytes(4,6);
    maxBalance = data.bytes(10,3);
    TTREF_C = data.bytes(13,4);
    TTREF_D = data.right(4);
    
      print ("data:          " + data)
      print ("MAC:           " + inquireAccMAC)    
      print ("refData:       " + referenceData)    
      print ("--tr. type:    " + transactionType);
      print ("--balance:     " + balance);
      print ("--ATREF:       " + ATREF);
      print ("--maxBalance:  " + maxBalance);
      print ("--TTREF_C:     " + TTREF_C);
      print ("--TTREF_D:     " + TTREF_D);

    //referenceData without the padding
    dataToEncrypt = referenceData.left(4).concat(transactionType).concat(balance).concat(ATREF).concat(new ByteString("00 00", HEX));

    deskey.setComponent(Key.DES, certifyKey);
    expectedMAC = crypto.encrypt(deskey, Crypto.DES_CBC, dataToEncrypt, IvAccount);

    print ("expectedMAC: " + expectedMAC)    

    assert(inquireAccMAC.equals(expectedMAC.right(8).left(4)));
    print("All the MACs are correct =)")
    print ("TRACE --- Inquire Account with Secure Messaging - Done");
  }
}

function revokeDebitSM(){
	amountRevoke = new ByteString("00 0F A0", HEX); //4000 -> 40 euros

	newATREF = ATREF.add(1);
	balanceMAC = balance.add(amountRevoke.toSigned())
	
	print("balance :" +balance);
	print("balanceToRestore :" +balanceMAC);

	revokeDebitChecksum = new ByteString("E8", HEX).concat(balanceMAC).concat(TTREF_D).concat(newATREF).concat(new ByteString("00 00", HEX));
	deskey.setComponent(Key.DES, revokeDebitKey);
	
	MAC = crypto.encrypt(deskey, Crypto.DES_CBC, revokeDebitChecksum, IvAccount);
	
	deskey.setComponent(Key.DES, Ks);

    revokeDebitData = MAC.right(8).left(4);

    encriptedData = crypto.encrypt(deskey, Crypto.DES_CBC, revokeDebitData.pad(Crypto.ISO9797_METHOD_2), seqNumber);

    paddingInd = "0" + (revokeDebitData.pad(Crypto.ISO9797_METHOD_2).length - revokeDebitData.length).toString(16);
    P3 = (9 + encriptedData.length);
    responseLength = (P3+1).toString(16)
    L87 = (encriptedData.length+1).toString(16);
    if (L87.length == 1) L87 = "0" + L87;
    print("P3 ", P3, "padding", paddingInd,  "l87", L87,"data:  ", encriptedData.toString(), "expected response length:", responseLength);

    revokeDebitAccApdu = new ByteString("8C E8 00 00", HEX);
    commandHeaderTLV =  new ByteString("89 04", HEX).concat(revokeDebitAccApdu);  
    secureData = new ByteString("87" + L87 + paddingInd, HEX).concat(encriptedData);

    AuthCode = commandHeaderTLV.concat(secureData).pad(Crypto.ISO9797_METHOD_2, true);
    encryptedAuthCode = crypto.encrypt(deskey, Crypto.DES_CBC, AuthCode, seqNumber);

    MAC = encryptedAuthCode.right(8).left(4);
    
    print("APDU: " + revokeDebitAccApdu.concat(new ByteString(P3.toString(16), HEX)).concat(secureData).concat(new ByteString("8E 04", HEX)).concat(MAC));
    card.plainApdu(revokeDebitAccApdu.concat(new ByteString(P3.toString(16), HEX)).concat(secureData).concat(new ByteString("8E 04", HEX)).concat(MAC));
    print("Código SW: " + card.SW.toString(16));
}

function verifyRevokeDebitSM(){
  getResponseApdu  = "80 C0 00 00 0C"//.concat(responseLength);
  response = card.plainApdu(new ByteString(getResponseApdu, HEX));
  print ("resp: " + response);
  swStatus = response.left(4).right(2);
  intents = swStatus.right(1)
  print (" -x-x-x-x-x-x- Account Status after RevokeDebit: " +swStatus + " -x-x-x-x-x-x- ");
   //----------------------------------------------- Verify SM MAC  
  if (response != "") {
    print ("TRACE --- RevokeDebit - Checking Secure RevokeDebit Response");

    receivedMac = response.right(4);
    macVerifier = commandHeaderTLV.concat(response.left(4)).pad(Crypto.ISO9797_METHOD_2, true);

    encryptedMacVerifier = crypto.encrypt(deskey, Crypto.DES_CBC, macVerifier, seqNumber).right(8).left(4);

    print ("Received MAC:   " + receivedMac);
    print ("Verifier MAC:   " + encryptedMacVerifier);
    
    assert(receivedMac.equals(encryptedMacVerifier));
    print ("Received MAC Encripted with Ks - ok");
//-----------------------------------------------------
    print ("TRACE --- RevokeDebit Account with Secure Messaging Done Correctly");
  }
}

print (" -x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x1"); 
mutualAuth();
print (" -x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x2");
inquireSM();
seqNumber = seqNumber.add(1);
print (" -x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x3");
getInquireResponse();
seqNumber = seqNumber.add(1);
print (" -x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x4");
revokeDebitSM();
seqNumber = seqNumber.add(1);
print (" -x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x5");
verifyRevokeDebitSM();
seqNumber = seqNumber.add(1);
print (" -x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x6");
inquireSM();
seqNumber = seqNumber.add(1);
print (" -x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x7");
getInquireResponse();
if (intents.toString() != "00") print ("intents: ", intents)