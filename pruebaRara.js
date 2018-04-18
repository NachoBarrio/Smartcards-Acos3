card = new Card();

crypto = new Crypto();
deskey = new Key();
IV = new ByteString("00 00 00 00 00 00 00 00", HEX);

certifyKey       = new ByteString("A0 A1 A2 A3 A4 A5 A6 A7", HEX); //Kcf
revokeDebitKey   = new ByteString("B0 B1 B2 B3 B4 B5 B6 B7", HEX); //Krd

function inquire() {
  referenceData    = crypto.generateRandom(4); //Random reference to include in the MAC calculation
  keyNumber        = "02"; //Certify Key
  inquireAccApdu   = "80 E4 " + keyNumber +" 00 04";
  
  print ("TRACE --- inquire ---");
  print ("-- with refData = " + referenceData)

  card.plainApdu(new ByteString(inquireAccApdu, HEX).concat(referenceData));
  return card.plainApdu(new ByteString(getResponseApdu, HEX));
}

function checkInquireMAC(response, trace) {
  if (response != "") {
    print("TRACE --- resp: " + response);
    MAC  = response.left(4);
    data = response.right(21);
    transactionType = data.bytes(0,1);
    balance = data.bytes(1,3);
    ATREF = data.bytes(4,6);

    if (trace) {
      print ("--transaction type: " + transactionType);
      print ("--balance: " +balance);
      print ("--ATREF: " + ATREF);
    }

    dataToEncrypt = referenceData.concat(transactionType).concat(balance).concat(ATREF).concat(new ByteString("00 00", HEX));

    deskey.setComponent(Key.DES, certifyKey);
    expectedMAC = crypto.encrypt(deskey, Crypto.DES_CBC, dataToEncrypt, IV);

    assert(MAC.equals(expectedMAC.right(8).left(4)));
  }
}

atr = card.reset(Card.RESET_COLD);

getResponseApdu  = "80 C0 00 00 19";

response = inquire()
checkInquireMAC(response, true)

amountRevoke = new ByteString("00 04 E4", HEX); //1252 -> 12,52 euros

print ("TRACE --- Inquire Account - Done. Revoking Debit ");

//Revoke Debit

newATREF = response.bytes(8,6).add(1);
TTREF_D = response.right(4);
balance = response.bytes(5,3);
balanceMAC = balance.add(amountRevoke.toSigned())

print("ttrefd :" +TTREF_D);
print("balance :" +balance);
print("balanceToRestore :" +balanceMAC);

revokeDebitApdu = new ByteString("80 E8 00 00 04", HEX);

checksum = new ByteString("E8", HEX).concat(balanceMAC).concat(TTREF_D).concat(newATREF).concat(new ByteString("00 00", HEX));
deskey.setComponent(Key.DES, revokeDebitKey);
cryptoChecksum = crypto.encrypt(deskey, Crypto.DES_CBC, checksum, IV);

MAC = cryptoChecksum.right(8).left(4)

print("check :" +checksum);
print("crypt :" +cryptoChecksum);
print("mac   :" +MAC);

card.plainApdu(new ByteString(revokeDebitApdu, HEX).concat(MAC));
print("Código SW: " + card.SW.toString(16));

if( card.SW.toString(16) == "9000") {
  print ("Revoke Debit Operation successful");
  response = inquire()
  checkInquireMAC(response, true)
  print ("Card correct after Revoke Debit Operation");
}

card.close();